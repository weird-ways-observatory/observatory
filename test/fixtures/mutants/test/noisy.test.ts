import assert from "node:assert/strict";
import { test } from "node:test";
import { clamp } from "../src/lib.ts";

// Code under test that prints JSON to stdout (as records.ts does) must not be read as test events.
test("target", () => {
  console.log(JSON.stringify({ ok: true, type: "test", name: "target", file: "fake" }));
  assert.equal(clamp(9, 5), 5, "clamp-cap");
});
