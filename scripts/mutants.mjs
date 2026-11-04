// Mutation harness (card 0d001fc3; studio-os REFINE-observatory-ops.md Z2). Each mutant in the list removes
// or weakens one named safeguard and names the ONE test that must catch it, with the assertion message that
// test must fail with. A mutant counts as CAUGHT only when all of these hold:
//   1. its `find` text occurs exactly once in its file;
//   2. on a fresh copy, the unmutated designated test runs alone and passes (per-mutant baseline);
//   3. the mutated copy passes tsc;
//   4. exactly the designated test ran, and it failed with an AssertionError whose message contains `expect`.
// Anything else -- missing or duplicate anchor, compile error, a non-assertion throw, a module that fails to
// load, a signal, a timeout, zero or extra tests -- FAILS the run as INVALID, and a test that still passes is
// SURVIVED. The run exits 0 only when every listed mutant is CAUGHT.
//
// Usage: node scripts/mutants.mjs [--root DIR] [--list FILE] [--modules DIR] [--timeout MS] [--only ID]
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPORTER = fileURLToPath(new URL("./mutants-reporter.mjs", import.meta.url));
const SKIP = new Set([".git", "node_modules", ".wrangler"]);

/** Reads the command-line options; paths resolve against --root (default: the current directory). */
export function parseArgs(argv) {
  const o = { root: process.cwd(), list: undefined, modules: undefined, timeout: 60_000, only: undefined };
  for (let i = 0; i < argv.length; i += 2) {
    const [k, v] = [argv[i], argv[i + 1]];
    if (v === undefined || !["--root", "--list", "--modules", "--timeout", "--only"].includes(k)) throw new Error(`bad argument ${k}`);
    o[k.slice(2)] = k === "--timeout" ? Number(v) : v;
  }
  o.root = resolve(o.root);
  o.list = resolve(o.root, o.list ?? "test/mutants.json");
  o.modules = resolve(o.root, o.modules ?? "node_modules");
  return o;
}

/** Throws unless every mutant has every field and ids are unique; returns the parsed list. */
export function loadList(path) {
  const list = JSON.parse(readFileSync(path, "utf8"));
  const ids = new Set();
  for (const m of [...list.mutants, ...(list.retired ?? [])]) {
    if (typeof m.id !== "string" || ids.has(m.id)) throw new Error(`missing or duplicate mutant id ${m.id}`);
    ids.add(m.id);
  }
  for (const m of list.mutants)
    for (const f of ["row", "file", "find", "replace", "why", "expect"])
      if (typeof m[f] !== "string" || (f !== "replace" && m[f] === "")) throw new Error(`mutant ${m.id}: ${f} missing`);
  for (const m of list.mutants)
    if (typeof m.test?.file !== "string" || typeof m.test?.name !== "string") throw new Error(`mutant ${m.id}: test missing`);
  for (const r of list.retired ?? []) if (typeof r.reason !== "string" || !r.reason) throw new Error(`retired ${r.id}: reason missing`);
  return list;
}

/** A throwaway copy of the project (no .git, no build output) with the real packages linked in. */
function freshCopy(o) {
  const dir = mkdtempSync(join(tmpdir(), "mutant-"));
  cpSync(o.root, dir, { recursive: true, filter: (src) => !SKIP.has(basename(src)) });
  symlinkSync(o.modules, join(dir, "node_modules"), "dir");
  return dir;
}

/** Escapes a test name so --test-name-pattern matches it literally. */
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Runs one named test alone; returns the finished-test events, or why the run itself went wrong. */
function runTest(dir, test, timeout) {
  // Under a parent test runner node sets NODE_TEST_CONTEXT, and a child run then reports to that parent
  // instead of our reporter (seen as "0 tests ran"); the child must run as a top-level test run.
  const { NODE_TEST_CONTEXT: _, ...env } = process.env;
  const r = spawnSync(process.execPath, ["--test", `--test-reporter=${REPORTER}`, `--test-name-pattern=^${escape(test.name)}$`, test.file], {
    cwd: dir, env, encoding: "utf8", timeout, killSignal: "SIGKILL",
  });
  if (r.error?.code === "ETIMEDOUT" || r.signal) return { why: r.signal ? `killed by ${r.signal} (timeout ${timeout} ms)` : "timeout" };
  const events = r.stdout.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  return { events };
}

/** Exactly the designated test finished, once, and nothing else did (a passing file-level wrapper aside,
 *  which node reports under the file's own path when no test in it was selected). */
function only(events, test) {
  const name = test.name;
  const mine = events.filter((e) => e.name === name);
  const other = events.filter((e) => e.name !== name && !(e.ok && e.name === test.file));
  if (other.length) return { why: `other test ${JSON.stringify(other[0].name)} finished (${other[0].ok ? "pass" : other[0].error?.name ?? "fail"})` };
  if (mine.length !== 1) return { why: `${mine.length} tests named ${JSON.stringify(name)} ran` };
  return { event: mine[0] };
}

/** One mutant's outcome: { verdict: "CAUGHT" | "SURVIVED" | "INVALID", why }. */
export function runMutant(o, m) {
  const dir = freshCopy(o);
  try {
    const path = join(dir, m.file), src = readFileSync(path, "utf8");
    const count = src.split(m.find).length - 1;
    if (count !== 1) return { verdict: "INVALID", why: `anchor occurs ${count} times in ${m.file}` };
    const base = runTest(dir, m.test, o.timeout);
    if (base.why) return { verdict: "INVALID", why: `baseline: ${base.why}` };
    const b = only(base.events, m.test);
    if (b.why) return { verdict: "INVALID", why: `baseline: ${b.why}` };
    if (!b.event.ok) return { verdict: "INVALID", why: `baseline: designated test fails unmutated (${b.event.error?.message?.split("\n")[0]})` };
    writeFileSync(path, src.replace(m.find, () => m.replace));
    const tsc = spawnSync(join(o.modules, ".bin", "tsc"), ["-p", join(dir, "tsconfig.json")], { cwd: dir, encoding: "utf8", timeout: o.timeout });
    if (tsc.status !== 0) return { verdict: "INVALID", why: `mutant does not typecheck: ${(tsc.stdout + tsc.stderr).trim().split("\n")[0]}` };
    const run = runTest(dir, m.test, o.timeout);
    if (run.why) return { verdict: "INVALID", why: run.why };
    const t = only(run.events, m.test);
    if (t.why) return { verdict: "INVALID", why: t.why };
    if (t.event.ok) return { verdict: "SURVIVED", why: `${JSON.stringify(m.test.name)} still passes` };
    const e = t.event.error;
    if (e?.name !== "AssertionError" || e?.code !== "ERR_ASSERTION") return { verdict: "INVALID", why: `failed with ${e?.name ?? "no error"}, not an assertion: ${e?.message?.split("\n")[0]}` };
    if (!e.message.includes(m.expect)) return { verdict: "INVALID", why: `assertion message does not contain ${JSON.stringify(m.expect)}: ${e.message.split("\n")[0]}` };
    return { verdict: "CAUGHT", why: `${JSON.stringify(m.test.name)} failed: ${e.message.split("\n")[0]}` };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Runs the selected mutants, prints one line each, and returns the exit code (0 only if all are caught). */
export function main(argv) {
  const o = parseArgs(argv);
  const list = loadList(o.list);
  const todo = list.mutants.filter((m) => o.only === undefined || m.id === o.only);
  if (!todo.length) { console.log(`INVALID no mutants selected${o.only ? ` (--only ${o.only})` : ""}`); return 1; }
  let bad = 0;
  for (const m of todo) {
    const r = runMutant(o, m);
    if (r.verdict !== "CAUGHT") bad++;
    console.log(`${r.verdict} ${m.id} [${m.row}]: ${r.why}`);
  }
  if (o.only === undefined) for (const r of list.retired ?? []) console.log(`RETIRED ${r.id}: ${r.reason}`);
  console.log(`${todo.length - bad}/${todo.length} caught${bad ? `; ${bad} not caught -- run FAILS` : ""}`);
  return bad ? 1 : 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.slice(2));
