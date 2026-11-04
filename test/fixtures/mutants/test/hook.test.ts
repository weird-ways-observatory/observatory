import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { clamp } from "../src/lib.ts";

// The assertion is in a hook, not the test body: must never count as the test catching a mutant.
beforeEach(() => assert.equal(clamp(9, 5), 5, "clamp-cap"));
test("target", () => {});
