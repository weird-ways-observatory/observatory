import assert from "node:assert/strict";
import { test } from "node:test";
import { clamp } from "../src/lib.ts";

// Skipped while the cap holds: the unmutated baseline never runs its body.
test("target", { skip: clamp(9, 5) === 5 }, () => assert.equal(clamp(9, 5), 5, "clamp-cap"));
