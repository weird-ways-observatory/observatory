// Fixture for the mutation harness self-tests (test/mutants.test.ts). Not used by the Observatory.
export function clamp(n: number, max: number): number {
  if (n > max) return max;
  return n;
}

export function spin(limit: number): number {
  let i = 0;
  while (i < limit) i++;
  return i;
}
