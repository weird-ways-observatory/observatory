// Test reporter for scripts/mutants.mjs: one JSON line per finished test, so the harness can see exactly
// which tests ran and why one failed. Node's own counts cannot be trusted for this: a name pattern that
// matches nothing still reports the file itself as one passing test (checked on node 22.23, card 0d001fc3).
export default async function* reporter(source) {
  for await (const e of source) {
    if (e.type !== "test:pass" && e.type !== "test:fail") continue;
    // Everything the harness needs to tell a genuine kill from a lookalike (Codex B0 r1 #1-#4): whether this is
    // a test or a describe() suite, where it is defined, whether it was skipped, and where it failed.
    const err = e.data.details?.error, cause = err?.cause;
    yield `${JSON.stringify({
      ok: e.type === "test:pass",
      type: e.data.details?.type,
      name: e.data.name,
      file: e.data.file,
      skip: e.data.skip !== undefined && e.data.skip !== false,
      todo: e.data.todo !== undefined && e.data.todo !== false,
      failureType: err?.failureType,
      error: cause && { name: cause.name, code: cause.code, message: String(cause.message ?? cause) },
    })}\n`;
  }
}
