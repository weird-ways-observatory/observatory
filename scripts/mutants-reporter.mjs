// Test reporter for scripts/mutants.mjs: one JSON line per finished test, so the harness can see exactly
// which tests ran and why one failed. Node's own counts cannot be trusted for this: a name pattern that
// matches nothing still reports the file itself as one passing test (checked on node 22.23, card 0d001fc3).
export default async function* reporter(source) {
  for await (const e of source) {
    if (e.type !== "test:pass" && e.type !== "test:fail") continue;
    const cause = e.data.details?.error?.cause;
    yield `${JSON.stringify({
      ok: e.type === "test:pass",
      name: e.data.name,
      file: e.data.file,
      error: cause && { name: cause.name, code: cause.code, message: String(cause.message ?? cause) },
    })}\n`;
  }
}
