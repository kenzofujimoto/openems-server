import { diffPolicies } from "./policyDiff";

describe("policy diff", () => {
  it("reports changed, added and removed keys with their paths", () => {
    expect(diffPolicies(
      { web_filter: { category_actions: { games: "monitor", adult: "block" }, monitor_all: true } },
      { web_filter: { category_actions: { games: "block", social: "allow" } }, app_control: { blocked: [] } },
    )).toEqual([
      { kind: "added", path: "app_control", value: '{"blocked":[]}' },
      { kind: "removed", path: "web_filter.category_actions.adult", value: "block" },
      { kind: "changed", path: "web_filter.category_actions.games", before: "monitor", after: "block" },
      { kind: "added", path: "web_filter.category_actions.social", value: "allow" },
      { kind: "removed", path: "web_filter.monitor_all", value: "true" },
    ]);
  });

  it("compares lists by item and reports a pure reorder", () => {
    const a = { domain: "a.example", action: "block" };
    const b = { domain: "b.example", action: "allow" };
    expect(diffPolicies({ rules: [a, b] }, { rules: [b, a] })).toEqual([{ kind: "reordered", path: "rules" }]);
    expect(diffPolicies({ rules: [a] }, { rules: [b] })).toEqual([
      { kind: "removed", path: "rules", value: JSON.stringify(a) },
      { kind: "added", path: "rules", value: JSON.stringify(b) },
    ]);
    expect(diffPolicies({ x: 1 }, { x: 1 })).toEqual([]);
    expect(diffPolicies(undefined, "v")).toEqual([{ kind: "added", path: "", value: "v" }]);
    expect(diffPolicies("v", undefined)).toEqual([{ kind: "removed", path: "", value: "v" }]);
  });
});
