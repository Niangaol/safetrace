import { test } from "node:test";
import assert from "node:assert/strict";
import { CircuitBreaker } from "../src/circuit.js";

test("failed half-open probes reopen with a fresh cooldown, then allow one new probe", () => {
  let now = 0;
  const breaker = new CircuitBreaker("probe", { failureThreshold: 2, openMs: 100, now: () => now });
  assert.equal(breaker.allow(), true);
  breaker.onFailure();
  assert.equal(breaker.state().status, "closed");
  breaker.onFailure();
  assert.equal(breaker.state().status, "open", "epoch zero is a valid opening time");
  assert.equal(breaker.state().opened_at, new Date(0).toISOString());
  assert.equal(breaker.allow(), false);
  for (let cycle = 0; cycle < 3; cycle++) {
    now += 100;
    assert.equal(breaker.state().status, "half_open");
    assert.equal(breaker.allow(), true);
    assert.equal(breaker.allow(), false, "only one in-flight probe");
    now += 10;
    breaker.onFailure();
    assert.equal(breaker.state().status, "open");
    assert.equal(breaker.state().opened_at, new Date(now).toISOString());
    now += 99;
    assert.equal(breaker.allow(), false, "cooldown starts at failed probe completion");
    now -= 99;
  }
  now += 100;
  assert.equal(breaker.allow(), true);
  breaker.onSuccess();
  assert.equal(breaker.state().status, "closed");
  assert.equal(breaker.state().opened_at, null);
  assert.equal(breaker.state().consecutive_failures, 0);
  assert.equal(breaker.allow(), true);
});
