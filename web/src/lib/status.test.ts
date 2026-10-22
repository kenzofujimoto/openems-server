import { endpoints } from "@/mocks/data";
import { connectionStatus, policyStatus, summarize } from "./status";
import type { Endpoint } from "./schemas";

const base = endpoints[0] as Endpoint;

describe("policyStatus", () => {
  it("is applied only when the confirmed policy matches the desired one", () => {
    expect(policyStatus(base)).toBe("applied");
    expect(policyStatus({ ...base, applied_digest: "stale" })).toBe("pending");
    expect(policyStatus({ ...base, applied_vdom: "Strict" })).toBe("pending");
  });

  it("reports errors before anything else", () => {
    expect(policyStatus({ ...base, last_error: "enforcement failed" })).toBe("error");
  });

  it("treats an acknowledged release of an unassigned group as applied", () => {
    const released = { ...base, desired_profile: null, applied_vdom: base.effective_vdom, applied_digest: "" };
    expect(policyStatus(released)).toBe("applied");
    expect(policyStatus({ ...released, last_applied: null })).toBe("pending");
  });
});

describe("connectionStatus", () => {
  it("separates online, offline and revoked devices", () => {
    expect(connectionStatus(base)).toBe("online");
    expect(connectionStatus({ ...base, online: false })).toBe("offline");
    expect(connectionStatus({ ...base, status: "unregistered" })).toBe("revoked");
  });
});

describe("summarize", () => {
  it("counts the fleet by connection and policy state", () => {
    expect(summarize(endpoints as Endpoint[])).toEqual({
      total: 10, online: 9, offline: 1, applied: 8, pending: 1, error: 1,
    });
  });
});
