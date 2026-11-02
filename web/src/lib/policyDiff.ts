/** Human-readable differences between two policy bodies, for the review before publishing. */
export type Change =
  | { kind: "changed"; path: string; before: string; after: string }
  | { kind: "added" | "removed"; path: string; value: string }
  | { kind: "reordered"; path: string };

const show = (value: unknown) => typeof value === "string" ? value : JSON.stringify(value);
const isRecord = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);

function walk(before: unknown, after: unknown, path: string, out: Change[]) {
  if (JSON.stringify(before) === JSON.stringify(after)) return;
  if (isRecord(before) && isRecord(after)) {
    for (const key of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
      const next = path ? `${path}.${key}` : key;
      if (!(key in after)) out.push({ kind: "removed", path: next, value: show(before[key]) });
      else if (!(key in before)) out.push({ kind: "added", path: next, value: show(after[key]) });
      else walk(before[key], after[key], next, out);
    }
    return;
  }
  if (Array.isArray(before) && Array.isArray(after)) {
    // Lists are compared by item; a pure reorder matters for first-match rules, so it is reported too.
    const left = before.map(show);
    const right = after.map(show);
    const removed = left.filter((item) => !right.includes(item));
    const added = right.filter((item) => !left.includes(item));
    for (const value of removed) out.push({ kind: "removed", path, value });
    for (const value of added) out.push({ kind: "added", path, value });
    if (!removed.length && !added.length) out.push({ kind: "reordered", path });
    return;
  }
  if (before === undefined) out.push({ kind: "added", path, value: show(after) });
  else if (after === undefined) out.push({ kind: "removed", path, value: show(before) });
  else out.push({ kind: "changed", path, before: show(before), after: show(after) });
}

export function diffPolicies(before: unknown, after: unknown): Change[] {
  const out: Change[] = [];
  walk(before, after, "", out);
  return out;
}
