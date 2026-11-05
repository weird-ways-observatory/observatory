import assert from "node:assert/strict";
import { test } from "node:test";
import { clamp } from "../src/lib.ts";

// Registers the named test, then the module throws: the load failure must not be lost (Codex B0 r2).
test("target", () => assert.equal(clamp(9, 5), 5, "clamp-cap"));
throw new TypeError("module-load-after-registration");
