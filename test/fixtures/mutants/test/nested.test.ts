import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { clamp } from "../src/lib.ts";

// A genuine kill inside a describe() group still counts.
describe("grp", () => {
  test("target", () => assert.equal(clamp(9, 5), 5, "clamp-cap"));
});
