import assert from "node:assert/strict";
import { test } from "node:test";
import { clamp } from "../src/lib.ts";

// The stated limit (Codex B0 r3): after an awaited test has reported, a later module error is not seen. The kill
// still stands -- the named test's own assertion failed -- so the harness reports CAUGHT; this pins that boundary.
const actual = clamp(9, 5);
await test("target", () => assert.equal(actual, 5, "clamp-cap"));
if (actual !== 5) throw new TypeError("module-load-after-awaited-test");
