package workers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lsongdev/yabber"
	"github.com/lsongdev/yabber/workers"
)

func run(t *testing.T, handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestRequestAndResponse(t *testing.T) {
	worker, err := workers.New(`
export default {
  async fetch(request, env, ctx) {
    ctx.waitUntil(Promise.resolve());
    const input = await request.json();
    return Response.json(
      { method: request.method, url: request.url, agent: request.headers.get("user-agent"), sum: input.a + input.b, name: env.NAME },
      { status: 201, headers: { "X-Worker": "yes" } },
    );
  }
}`, map[string]string{"NAME": "yabber"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "http://example.com/path?q=1", strings.NewReader(`{"a":1,"b":2}`))
	request.Header.Set("User-Agent", "test")
	response := run(t, worker, request)
	want := `{"method":"POST","url":"http://example.com/path?q=1","agent":"test","sum":3,"name":"yabber"}`
	if response.Code != 201 || response.Body.String() != want {
		t.Fatalf("response = (%d, %s)", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/json" || response.Header().Get("X-Worker") != "yes" {
		t.Fatalf("headers = %v", response.Header())
	}
}

func TestCompileErrorsAreReportedEarly(t *testing.T) {
	for name, script := range map[string]string{
		"syntax":    `export default { fetch( }`,
		"no export": `function fetch() {}`,
		"no fetch":  `export default { other() {} }`,
	} {
		if _, err := workers.New(script, nil); err == nil {
			t.Errorf("%s: compiled without error", name)
		}
	}
}

func TestErrorsBecomeServerErrors(t *testing.T) {
	for name, script := range map[string]string{
		"throws":         `export default { fetch() { throw new Error("boom") } }`,
		"rejects":        `export default { async fetch() { throw new Error("boom") } }`,
		"wrong type":     `export default { fetch() { return "text" } }`,
		"never resolves": `export default { fetch() { return new Promise(() => {}) } }`,
	} {
		worker, err := workers.New(script, nil)
		if err != nil {
			t.Fatal(err)
		}
		if response := run(t, worker, httptest.NewRequest("GET", "/", nil)); response.Code != 500 {
			t.Errorf("%s: status = %d", name, response.Code)
		}
	}
}

func TestRunawayScriptStopsWithRequest(t *testing.T) {
	worker, err := workers.New(`export default { fetch(request) {
		if (request.url.endsWith("/loop")) { for (;;) {} }
		return new Response("ok");
	} }`, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	response := run(t, worker, httptest.NewRequest("GET", "/loop", nil).WithContext(ctx))
	if response.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d", response.Code)
	}
	if response := run(t, worker, httptest.NewRequest("GET", "/", nil)); response.Body.String() != "ok" {
		t.Fatalf("worker unusable after interrupt: %q", response.Body.String())
	}
}

func TestConcurrentRequests(t *testing.T) {
	worker, err := workers.New(`export default { fetch(request) { return new Response(request.method) } }`, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if response := run(t, worker, httptest.NewRequest("PUT", "/", nil)); response.Body.String() != "PUT" {
				t.Errorf("body = %q", response.Body.String())
			}
		})
	}
	wg.Wait()
}

func TestYabberIntegration(t *testing.T) {
	config, err := yabber.Parse([]byte(`
listeners: [{name: http, address: ":0"}]
sites:
  - hosts: [inline.example.com]
    worker: |
      export default { fetch(request) { return new Response("inline") } }
  - hosts: [env.example.com]
    worker:
      env: {NAME: env}
      script: |
        export default { fetch(request, env) { return new Response(env.NAME) } }
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := yabber.Validate(config); err == nil {
		t.Fatal("worker handler accepted without registering the extension")
	}
	server, err := yabber.New(config, workers.Option())
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := server.Handler("http")
	for host, want := range map[string]string{"inline.example.com": "inline", "env.example.com": "env"} {
		if body := run(t, handler, httptest.NewRequest("GET", "http://"+host+"/", nil)).Body.String(); body != want {
			t.Errorf("%s: body = %q", host, body)
		}
	}

	config.Sites[0].Extensions["worker"] = "export default { fetch( }"
	if err := yabber.Validate(config, workers.Option()); err == nil {
		t.Fatal("syntax error was not reported at configuration time")
	}
}
