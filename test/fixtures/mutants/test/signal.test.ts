import assert from "node:assert/strict";
import { after, test } from "node:test";
import { clamp } from "../src/lib.ts";

// When the cap is removed the process kills itself just after the assertion is reported.
test("target", () => {
  if (clamp(9, 5) !== 5) setTimeout(() => process.kill(process.pid, "SIGKILL"), 20);
  assert.equal(clamp(9, 5), 5, "clamp-cap");
});
after(() => new Promise((done) => setTimeout(done, 300)));
