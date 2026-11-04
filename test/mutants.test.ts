// Self-tests for the mutation harness (scripts/mutants.mjs, card 0d001fc3): it must count a mutant as caught
// only for a genuine assertion failure of the one named test, and fail the run for every other outcome.
// Each case runs the real command against the fixture project in test/fixtures/mutants.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, test } from "node:test";

const run = (...args: string[]) => {
  const r = spawnSync(process.execPath, ["scripts/mutants.mjs", "--root", "test/fixtures/mutants", "--modules", `${process.cwd()}/node_modules`, "--timeout", "4000", ...args], { encoding: "utf8" });
  return { code: r.status, out: r.stdout + r.stderr };
};
const one = (id: string) => run("--only", id);

describe("mutation harness", { concurrency: true }, () => {
  const cases: [string, number, RegExp][] = [
    ["kill", 0, /^CAUGHT kill \[self\]: "clamp caps at max" failed: clamp-cap$/m],
    ["survivor", 1, /^SURVIVED survivor .*still passes$/m],
    ["missing-anchor", 1, /^INVALID missing-anchor .*anchor occurs 0 times/m],
    ["duplicate-anchor", 1, /^INVALID duplicate-anchor .*anchor occurs 3 times/m],
    ["compile-error", 1, /^INVALID compile-error .*does not typecheck: .*TS2322/m],
    ["runtime-throw", 1, /^INVALID runtime-throw .*failed with TypeError, not an assertion: boom$/m],
    ["module-load", 1, /^INVALID module-load .*other test "test\/lib\.test\.ts" finished \(fail\)$/m],
    ["timeout", 1, /^INVALID timeout .*killed by SIGKILL \(timeout 4000 ms\)$/m],
    ["zero-tests", 1, /^INVALID zero-tests .*baseline: 0 tests named "clamp caps" ran$/m],
    ["wrong-message", 1, /^INVALID wrong-message .*does not contain "some-other-message"/m],
    ["baseline-fails", 1, /^INVALID baseline-fails .*baseline: designated test fails unmutated \(broken-baseline\)$/m],
  ];
  for (const [id, code, line] of cases)
    test(`fixture mutant ${id}`, () => {
      const r = one(id);
      assert.match(r.out, line, `fixture ${id} output: ${r.out}`);
      assert.equal(r.code, code, `fixture ${id} exit code: ${r.out}`);
    });

  test("a whole run fails when any mutant is not caught, and lists retired entries", () => {
    const r = run();
    assert.match(r.out, /^1\/11 caught; 10 not caught -- run FAILS$/m, r.out);
    assert.match(r.out, /^RETIRED old: fixture: shows a retired entry is listed$/m, r.out);
    assert.equal(r.code, 1);
  });

  test("an id that selects nothing fails the run", () => {
    const r = one("no-such-mutant");
    assert.match(r.out, /^INVALID no mutants selected \(--only no-such-mutant\)$/m, r.out);
    assert.equal(r.code, 1);
  });
});
