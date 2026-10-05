import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";

const guard = new URL("../../../scripts/test-network-guard.mjs", import.meta.url).href;
function child(code: string) {
  return spawnSync(process.execPath, ["--import", guard, "--input-type=module", "-e", code], { encoding: "utf8", timeout: 15_000 });
}
const attempts: Record<string, string> = {
  fetch: 'await fetch("https://example.invalid/secret?key=hidden")',
  "fetch Request": 'await fetch(new Request("https://example.invalid/"))',
  http: '(await import("node:http")).get("http://example.invalid/")',
  https: '(await import("node:https")).request({hostname:"example.invalid", port:443})',
  "http named export": '(await import("node:http")).request({hostname:"203.0.113.1"})',
  net: '(await import("node:net")).connect(443, "203.0.113.1")',
  "net createConnection": '(await import("node:net")).createConnection({port:443,host:"203.0.113.1"})',
  "custom lookup": '(await import("node:net")).connect({port:443,host:"localhost",lookup:(_host,_opts,callback)=>callback(null,[{address:"203.0.113.1",family:4}])})',
  tls: '(await import("node:tls")).connect({port:443, host:"203.0.113.1"})',
  http2: '(await import("node:http2")).connect("https://example.invalid")',
  dns: '(await import("node:dns")).lookup("example.invalid", () => {})',
  "dns promises": 'await (await import("node:dns/promises")).resolve4("example.invalid")',
  "dns Resolver": 'new (await import("node:dns")).Resolver().resolve4("example.invalid", () => {})',
  "UDP connect": '(await import("node:dgram")).createSocket("udp4").connect(53, "203.0.113.1")',
  "UDP send": '(await import("node:dgram")).createSocket("udp4").send(Buffer.from("x"), 53, "203.0.113.1")',
  "UDP send offset": '(await import("node:dgram")).createSocket("udp4").send(Buffer.from("x"), 0, 1, 53, "203.0.113.1")',
};
for (const [name, attempt] of Object.entries(attempts)) {
  test("network guard blocks " + name + " even when the error is swallowed", () => {
    const result = child('try { ' + attempt + '; } catch {} process.exitCode = 0; process.exit(0);');
    assert.ifError(result.error);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /TEST_NETWORK_BLOCKED/);
    assert.ok(!result.stderr.includes("key=hidden"), "guard must not print credentials");
  });
}

test("network guard preserves mocks, local HTTP stubs, and ordinary Node child inheritance", () => {
  const result = child(
    'import {createServer, get} from "node:http"; import {spawnSync} from "node:child_process"; ' +
    'const server = createServer((req,res) => res.end("stub")); ' +
    'await new Promise(r => server.listen(0,"127.0.0.1",r)); ' +
    'try { const url = "http://127.0.0.1:" + server.address().port; ' +
    'if (await (await fetch(url)).text() !== "stub") throw Error("fetch stub failed"); ' +
    'await new Promise((resolve,reject) => get(url,res => {res.resume(); res.on("end",resolve);}).on("error",reject)); ' +
    'const original = fetch; globalThis.fetch = async () => new Response("mock"); ' +
    'if (await (await fetch("https://example.invalid")).text() !== "mock") throw Error("mock failed"); globalThis.fetch = original; ' +
    'const nested = spawnSync(process.execPath,["--input-type=module","-e",' + JSON.stringify('try {await fetch("https://example.invalid")} catch {}') + '],{encoding:"utf8"}); ' +
    'if (nested.status !== 1 || !nested.stderr.includes("TEST_NETWORK_BLOCKED")) throw Error("child guard missing"); ' +
    '} finally {await new Promise(r => server.close(r));}'
  );
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});

test("network guard follows local stub redirects and preserves manual redirect mode", () => {
  const result = child(
    'import {createServer} from "node:http"; const s = createServer((req,res) => {if(req.url==="/start"){res.writeHead(302,{location:"/end"});res.end();}else{res.end("redirect stub");}}); ' +
    'await new Promise(r=>s.listen(0,"127.0.0.1",r)); const url="http://localhost:"+s.address().port+"/start"; ' +
    'try {if(await (await fetch(url)).text()!=="redirect stub") throw Error("local redirect failed"); ' +
    'if((await fetch(new Request(url,{redirect:"manual"}))).status!==302) throw Error("manual redirect changed");} ' +
    'finally {await new Promise(r=>s.close(r));}'
  );
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});

test("network guard blocks a local stub redirect before an external connection", () => {
  const result = child(
    'import {createServer} from "node:http"; const s = createServer((req,res) => {res.writeHead(302,{location:"http://203.0.113.1"});res.end();}); ' +
    'await new Promise(r => s.listen(0,"127.0.0.1",r)); ' +
    'try {await fetch("http://127.0.0.1:"+s.address().port).catch(()=>{});} finally {await new Promise(r=>s.close(r));}'
  );
  assert.ifError(result.error);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /TEST_NETWORK_BLOCKED/);
});

test("network guard makes a successful business fallback fail the test process", () => {
  const result = spawnSync(process.execPath, ["--import", guard, "--import", "tsx", "--input-type=module", "-e",
    'import {test} from "node:test"; import assert from "node:assert/strict"; import {ModelGateway} from "./src/gateway/src/index.ts"; ' +
    'test("business fallback", async () => { const r = await new ModelGateway({forceProvider:"deepseek"}).chat("answerer",[{role:"user",content:"guard regression"}]); assert.equal(r.provider,"cache"); });'
  ], { encoding: "utf8", timeout: 15_000, env: { ...process.env, DEEPSEEK_BASE_URL: "https://example.invalid/v1", DEEPSEEK_API_KEY: "not-real" } });
  assert.ifError(result.error);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /TEST_NETWORK_BLOCKED/);
});
