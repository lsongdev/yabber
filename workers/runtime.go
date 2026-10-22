package workers

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"

	"github.com/dop251/goja"
)

// MaxBodyBytes bounds request bodies read into a worker.
const MaxBodyBytes = 10 << 20

//go:embed prelude.js
var preludeSource string

var prelude = goja.MustCompile("prelude.js", preludeSource, true)

// Module syntax is rewritten to script syntax, which goja runs directly.
var (
	exportDefault  = regexp.MustCompile(`\bexport\s+default\s+`)
	exportFunction = regexp.MustCompile(`(?m)^export\s+((?:async\s+)?function\b)`)
	exportBinding  = regexp.MustCompile(`(?m)^export\s+((?:const|let|var|class)\b)`)
)

// Worker runs a script written in the Cloudflare Workers module syntax:
//
//	export default {
//	  async fetch(request, env, ctx) {
//	    return new Response("hello");
//	  }
//	}
//
// The script is compiled once. Each request runs on a JavaScript runtime
// taken from a pool, so, as on Cloudflare, global state may persist between
// requests but is never shared by concurrent ones. Execution stops when the
// request's context is done.
type Worker struct {
	program *goja.Program
	env     map[string]string
	pool    sync.Pool // of *instance
}

type instance struct {
	vm       *goja.Runtime
	exports  *goja.Object
	fetch    goja.Callable
	request  goja.Value // the Request constructor
	response goja.Callable
	env      goja.Value
	ctx      goja.Value
}

// New compiles script, reporting syntax errors and a missing fetch handler
// immediately.
func New(script string, env map[string]string) (*Worker, error) {
	source := exportDefault.ReplaceAllString(script, "var __exports = ")
	source = exportFunction.ReplaceAllString(source, "$1")
	source = exportBinding.ReplaceAllString(source, "$1")
	program, err := goja.Compile("worker.js", source, false)
	if err != nil {
		return nil, err
	}
	w := &Worker{program: program, env: env}
	first, err := w.newInstance()
	if err != nil {
		return nil, err
	}
	w.pool.Put(first)
	return w, nil
}

func (w *Worker) newInstance() (*instance, error) {
	vm := goja.New()
	if _, err := vm.RunProgram(prelude); err != nil {
		return nil, err
	}
	if _, err := vm.RunProgram(w.program); err != nil {
		return nil, err
	}
	exported := vm.Get("__exports")
	if exported == nil || goja.IsUndefined(exported) {
		return nil, errors.New("script has no default export")
	}
	exports := exported.ToObject(vm)
	fetch, ok := goja.AssertFunction(exports.Get("fetch"))
	if !ok {
		return nil, errors.New("default export has no fetch method")
	}
	response, _ := goja.AssertFunction(vm.Get("__response"))
	env := vm.NewObject()
	for key, value := range w.env {
		_ = env.Set(key, value)
	}
	ctx := vm.NewObject()
	noop := vm.ToValue(func() {})
	_ = ctx.Set("waitUntil", noop)
	_ = ctx.Set("passThroughOnException", noop)
	return &instance{
		vm: vm, exports: exports, fetch: fetch, request: vm.Get("Request"),
		response: response, env: env, ctx: ctx,
	}, nil
}

func (w *Worker) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		http.Error(rw, "read request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) > MaxBodyBytes {
		http.Error(rw, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	inst, _ := w.pool.Get().(*instance)
	if inst == nil {
		if inst, err = w.newInstance(); err != nil {
			http.Error(rw, "worker: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	stop := context.AfterFunc(r.Context(), func() { inst.vm.Interrupt(r.Context().Err()) })
	result, err := inst.call(r, body)
	if stop() {
		w.pool.Put(inst)
	} // otherwise the runtime may carry the interrupt; discard it

	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(r.Context().Err(), context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		http.Error(rw, "worker: "+err.Error(), status)
		return
	}
	for i := 0; i+1 < len(result.headers); i += 2 {
		rw.Header().Add(result.headers[i], result.headers[i+1])
	}
	rw.WriteHeader(result.status)
	_, _ = io.WriteString(rw, result.body)
}

type result struct {
	status  int
	headers []string
	body    string
}

func (inst *instance) call(r *http.Request, body []byte) (result, error) {
	vm := inst.vm
	headers := vm.NewObject()
	for name, values := range r.Header {
		for _, value := range values {
			_ = headers.Set(name, value)
		}
	}
	init := vm.NewObject()
	_ = init.Set("method", r.Method)
	_ = init.Set("headers", headers)
	if len(body) > 0 {
		_ = init.Set("body", string(body))
	}
	request, err := vm.New(inst.request, vm.ToValue(requestURL(r)), init)
	if err != nil {
		return result{}, err
	}

	value, err := inst.fetch(inst.exports, request, inst.env, inst.ctx)
	if err != nil {
		return result{}, err
	}
	// goja drains its job queue before returning, so a promise that only
	// awaited other promises is settled by now.
	if promise, ok := value.Export().(*goja.Promise); ok {
		switch promise.State() {
		case goja.PromiseStateFulfilled:
			value = promise.Result()
		case goja.PromiseStateRejected:
			return result{}, fmt.Errorf("fetch rejected: %v", promise.Result())
		default:
			return result{}, errors.New("fetch returned a promise that never settled")
		}
	}
	plain, err := inst.response(goja.Undefined(), value)
	if err != nil {
		return result{}, err
	}
	object := plain.ToObject(vm)
	var out result
	out.status = int(object.Get("status").ToInteger())
	out.body = object.Get("body").String()
	if err := vm.ExportTo(object.Get("headers"), &out.headers); err != nil {
		return result{}, err
	}
	if out.status < 100 || out.status > 999 {
		return result{}, fmt.Errorf("invalid response status %d", out.status)
	}
	return out, nil
}

func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}
