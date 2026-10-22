// Fetch API subset available to worker scripts. Bodies are strings.

class Headers {
  constructor(init) {
    this._map = new Map();
    if (init instanceof Headers) {
      init.forEach((value, name) => this.append(name, value));
    } else if (Array.isArray(init)) {
      for (const [name, value] of init) this.append(name, value);
    } else if (init) {
      for (const name of Object.keys(init)) this.append(name, init[name]);
    }
  }
  get(name) {
    const value = this._map.get(String(name).toLowerCase());
    return value === undefined ? null : value;
  }
  set(name, value) { this._map.set(String(name).toLowerCase(), String(value)); }
  append(name, value) {
    name = String(name).toLowerCase();
    const current = this._map.get(name);
    this._map.set(name, current === undefined ? String(value) : current + ", " + value);
  }
  has(name) { return this._map.has(String(name).toLowerCase()); }
  delete(name) { this._map.delete(String(name).toLowerCase()); }
  forEach(callback, self) { for (const [name, value] of this._map) callback.call(self, value, name, this); }
  entries() { return this._map.entries(); }
  keys() { return this._map.keys(); }
  values() { return this._map.values(); }
  [Symbol.iterator]() { return this._map.entries(); }
}

class Request {
  constructor(input, init) {
    init = init || {};
    this.url = String(input instanceof Request ? input.url : input);
    this.method = String(init.method || "GET").toUpperCase();
    this.headers = new Headers(init.headers);
    this._body = init.body == null ? "" : String(init.body);
  }
  text() { return Promise.resolve(this._body); }
  json() { return Promise.resolve(JSON.parse(this._body)); }
}

class Response {
  constructor(body, init) {
    init = init || {};
    this._body = body == null ? "" : String(body);
    this.status = init.status === undefined ? 200 : init.status;
    this.statusText = init.statusText || "";
    this.headers = new Headers(init.headers);
  }
  get ok() { return this.status >= 200 && this.status < 300; }
  text() { return Promise.resolve(this._body); }
  json() { return Promise.resolve(JSON.parse(this._body)); }
  clone() { return new Response(this._body, this); }
  static json(data, init) {
    const response = new Response(JSON.stringify(data), init);
    if (!response.headers.has("content-type")) response.headers.set("content-type", "application/json");
    return response;
  }
  static redirect(url, status) {
    return new Response(null, { status: status || 302, headers: { location: String(url) } });
  }
}

// __response converts a Response into a plain object for the Go side.
function __response(value) {
  if (!(value instanceof Response)) throw new TypeError("fetch must return a Response");
  const headers = [];
  value.headers.forEach((v, k) => headers.push(k, v));
  return { status: value.status, headers: headers, body: value._body };
}
