/** Default unit-test safety net. Not a security sandbox for hostile code/native subprocesses.
 * Mock transports may replace fetch; real Node network transports remain loopback-only.
 * Any attempted external call poisons the process exit status, even if fallback catches it.
 */
import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import http2 from "node:http2";
import dns from "node:dns";
import dnsPromises from "node:dns/promises";
import dgram from "node:dgram";
import { syncBuiltinESMExports } from "node:module";

let blocked = false;
function deny(boundary, target) {
  blocked = true;
  process.exitCode = 1;
  const error = new Error("TEST_NETWORK_BLOCKED: " + boundary + " refused non-loopback target " + String(target));
  error.code = "TEST_NETWORK_BLOCKED";
  // Log only the host, never URLs containing credentials/query strings.
  process.stderr.write(error.message + "\n");
  throw error;
}
process.on("exit", () => { if (blocked) process.exitCode = 1; });

function local(host) {
  const value = String(host ?? "localhost").toLowerCase().replace(/^\[|\]$/g, "");
  if (value === "localhost" || value === "::1" || value === "0:0:0:0:0:0:0:1") return true;
  if (net.isIP(value) === 4) return value.startsWith("127.");
  // IPv4-mapped loopback, including the normalized IPv6 form emitted by URL.
  return /^::ffff:127\./.test(value) || /^::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}$/.test(value);
}
function check(host, boundary) { if (!local(host)) deny(boundary, host); }
function checkUrl(value, boundary) {
  const url = new URL(value instanceof Request ? value.url : String(value));
  if (url.protocol !== "http:" && url.protocol !== "https:") deny(boundary, url.protocol);
  check(url.hostname, boundary);
}
function connection(args, boundary) {
  if (Array.isArray(args[0])) return connection(args[0], boundary);
  const first = args[0];
  const opts = first && typeof first === "object" ? first : null;
  const path = opts?.path ?? (typeof first === "string" && !/^\d+$/.test(first) ? first : undefined);
  if (path !== undefined) {
    // Local Unix sockets and Windows named pipes are used by test infrastructure.
    if (String(path).startsWith("\\\\") && !["\\\\.\\pipe\\", "\\\\?\\pipe\\"].some(prefix => String(path).startsWith(prefix))) deny(boundary, "remote pipe");
    return;
  }
  check(opts ? opts.host ?? opts.hostname : typeof args[1] === "string" ? args[1] : undefined, boundary);
  // A custom lookup must not resolve an allowed hostname to a non-loopback address.
  if (typeof opts?.lookup === "function") {
    const lookup = opts.lookup;
    args[0] = { ...opts, lookup(host, options, callback) {
      return lookup(host, options, (error, address, family) => {
        if (!error) {
          for (const row of Array.isArray(address) ? address : [{ address }]) check(row.address, "custom lookup");
        }
        callback(error, address, family);
      });
    } };
  }
}
const realFetch = globalThis.fetch;
globalThis.fetch = async function(input, init) {
  checkUrl(input, "fetch");
  // Never let native undici follow a redirect without validating the destination.
  let request = new Request(input, init);
  const redirect = request.redirect;
  for (let hops = 0; ; hops++) {
    const replay = request.clone();
    const response = await realFetch(request, { redirect: "manual" });
    const location = response.headers.get("location");
    if (![301, 302, 303, 307, 308].includes(response.status) || !location || redirect === "manual") return response;
    await response.body?.cancel();
    if (redirect === "error") throw new TypeError("fetch redirect disallowed");
    const next = new URL(location, request.url);
    checkUrl(next, "fetch redirect");
    if (hops >= 19) throw new TypeError("fetch redirect limit exceeded");
    const dropBody = ((response.status === 301 || response.status === 302) && request.method === "POST")
      || (response.status === 303 && !["GET", "HEAD"].includes(request.method));
    const headers = new Headers(request.headers);
    if (next.origin !== new URL(request.url).origin) {
      for (const name of ["authorization", "proxy-authorization", "cookie"]) headers.delete(name);
    }
    if (dropBody) for (const name of ["content-type", "content-length", "content-encoding", "content-language", "content-location"]) headers.delete(name);
    request = new Request(next, { method: dropBody ? "GET" : request.method, headers,
      body: dropBody ? undefined : replay.body, duplex: "half", signal: request.signal,
      credentials: request.credentials, mode: request.mode, cache: request.cache,
    });
  }
};
// undici can use optimized Socket subclasses that override prototype.connect.
for (const method of ["connect", "createConnection"]) {
  const original = net[method];
  net[method] = function(...args) {
    connection(args, "net." + method);
    return original.apply(this, args);
  };
}
const socketConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(...args) {
  connection(args, "net.Socket.connect");
  return socketConnect.apply(this, args);
};
const tlsConnect = tls.connect;
tls.connect = function(...args) {
  connection(args, "tls.connect");
  return tlsConnect.apply(this, args);
};
for (const transport of [http, https]) {
  for (const method of ["request", "get"]) {
    const original = transport[method];
    transport[method] = function(...args) {
      const first = args[0];
      if (typeof first === "string" || first instanceof URL) checkUrl(first, method);
      const options = first && typeof first === "object" && !(first instanceof URL) ? first : args[1];
      if (options && typeof options === "object" && !options.socketPath) check(options.hostname ?? options.host, method);
      return original.apply(this, args);
    };
  }
}
const http2Connect = http2.connect;
http2.connect = function(authority, ...args) {
  checkUrl(authority, "http2.connect");
  return http2Connect.call(this, authority, ...args);
};
const udpConnect = dgram.Socket.prototype.connect;
dgram.Socket.prototype.connect = function(port, address, ...args) {
  check(typeof address === "string" ? address : undefined, "dgram.connect");
  return udpConnect.call(this, port, address, ...args);
};
const udpSend = dgram.Socket.prototype.send;
dgram.Socket.prototype.send = function(...args) {
  const address = typeof args[2] === "number" ? args[4] : args[2];
  check(typeof address === "string" ? address : undefined, "dgram.send");
  return udpSend.apply(this, args);
};
// Deny external DNS as well: a blocked connection must not leak a DNS query first.
for (const api of [dns, dnsPromises, dns.Resolver.prototype, dnsPromises.Resolver.prototype]) {
  for (const method of ["lookup", "lookupService", "resolve", "resolve4", "resolve6", "resolveAny", "resolveCaa", "resolveCname", "resolveMx", "resolveNaptr", "resolveNs", "resolvePtr", "resolveSoa", "resolveSrv", "resolveTxt", "reverse"]) {
    const original = api[method];
    if (typeof original !== "function") continue;
    api[method] = function(host, ...args) {
      check(host, "dns." + method);
      // lookup(localhost) is pinned to loopback, independent of hosts/DNS configuration.
      if (method === "lookup" && String(host).toLowerCase() === "localhost") {
        const options = args[0];
        host = (options === 6 || options?.family === 6) ? "::1" : "127.0.0.1";
      } else if (method !== "lookup") {
        deny("dns." + method, "DNS resolution is not permitted in unit tests");
      }
      return original.call(this, host, ...args);
    };
  }
}
syncBuiltinESMExports();
// Node test workers inherit execArgv; ordinary Node subprocesses inherit NODE_OPTIONS.
const preload = "--import=" + import.meta.url;
if (!(process.env.NODE_OPTIONS ?? "").includes(preload)) {
  process.env.NODE_OPTIONS = ((process.env.NODE_OPTIONS ?? "") + " " + preload).trim();
}
