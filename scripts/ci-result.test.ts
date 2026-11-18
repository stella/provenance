import { expect, test } from "bun:test";

const root = new URL("../", import.meta.url);
const ci = await Bun.file(new URL(".github/workflows/ci.yml", root)).text();
const cla = await Bun.file(new URL(".github/workflows/cla.yml", root)).text();

function jobBodies(source: string): Map<string, string> {
  const jobsStart = source.indexOf("\njobs:\n");
  expect(jobsStart).toBeGreaterThanOrEqual(0);

  const bodies = new Map<string, string>();
  const jobsSource = source.slice(jobsStart + "\njobs:\n".length);
  const matches = [...jobsSource.matchAll(/^  ([\w-]+):\n/gm)];
  for (const [index, match] of matches.entries()) {
    const start = match.index + match[0].length;
    const end = matches[index + 1]?.index ?? jobsSource.length;
    bodies.set(match[1], jobsSource.slice(start, end));
  }
  return bodies;
}

function aggregateErrors(source: string): string[] {
  const jobs = jobBodies(source);
  const aggregate = jobs.get("ci-result");
  if (!aggregate) return ["ci-result is missing"];

  const needs = aggregate.match(/^    needs:\s*\[([^\]]*)\]/m)?.[1]
    .split(",")
    .map((name) => name.trim()) ?? [];
  const expected = [...jobs.keys()].filter((name) => name !== "ci-result");
  const errors: string[] = [];
  if (aggregate.match(/^    if:\s*(.+)$/m)?.[1].trim() !== "always()") {
    errors.push("ci-result must use if: always()");
  }
  if (needs.length !== expected.length || expected.some((name) => !needs.includes(name))) {
    errors.push("ci-result needs must cover every other job");
  }
  return errors;
}

function triggersOnMergeGroup(source: string): boolean {
  const beforeJobs = source.slice(0, source.indexOf("\njobs:\n"));
  return /^  merge_group:\n    types: \[checks_requested\]$/m.test(beforeJobs);
}

test("ci-result covers every CI validation job and always reports", () => {
  expect(aggregateErrors(ci)).toEqual([]);
});

test("CI and CLA workflows run for merge groups", () => {
  expect(triggersOnMergeGroup(ci)).toBe(true);
  expect(triggersOnMergeGroup(cla)).toBe(true);
});

test("the aggregate guard detects a missing dependency", () => {
  const mutated = ci.replace(
    "needs: [trust-check, rust, integration-real]",
    "needs: [trust-check, rust]",
  );
  expect(mutated).not.toBe(ci);
  expect(aggregateErrors(mutated)).toContain("ci-result needs must cover every other job");
});
