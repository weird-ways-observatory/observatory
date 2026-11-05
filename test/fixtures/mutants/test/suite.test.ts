import assert from "node:assert/strict";
import { after, describe, test } from "node:test";
import { clamp } from "../src/lib.ts";

// The suite's own hook fails when the cap is removed, besides the test's assertion.
describe("grp", () => {
  after(() => {
    if (clamp(9, 5) !== 5) throw new TypeError("suite hook");
  });
  test("target", () => assert.equal(clamp(9, 5), 5, "clamp-cap"));
});
