import assert from "node:assert/strict";
import { test } from "node:test";
import { clamp, spin } from "../src/lib.ts";

test("clamp caps at max", () => assert.equal(clamp(9, 5), 5, "clamp-cap"));
test("clamp keeps small", () => assert.equal(clamp(3, 5), 3, "clamp-keep"));
test("spin ends", () => assert.equal(spin(3), 3, "spin-ends"));
