import { formatDelta, relativeTime } from "./format";

describe("formatDelta", () => {
  it("formats growth, decline and no change", () => {
    expect(formatDelta(110, 100)).toEqual({ text: "+10%", tone: "up" });
    expect(formatDelta(75, 100)).toEqual({ text: "-25%", tone: "down" });
    expect(formatDelta(5, 5)).toEqual({ text: "0%", tone: "flat" });
  });

  it("handles an empty previous period", () => {
    expect(formatDelta(3, 0)).toEqual({ text: "novo", tone: "up" });
    expect(formatDelta(0, 0)).toEqual({ text: "0%", tone: "flat" });
  });
});

describe("relativeTime", () => {
  const now = Date.parse("2026-10-22T13:00:00Z");

  it("uses short Portuguese labels", () => {
    expect(relativeTime("2026-10-22T12:59:40Z", now)).toBe("agora");
    expect(relativeTime("2026-10-22T12:51:00Z", now)).toBe("há 9 min");
    expect(relativeTime("2026-10-22T10:00:00Z", now)).toBe("há 3 h");
    expect(relativeTime("2026-10-19T13:00:00Z", now)).toBe("há 3 d");
  });

  it("returns a dash for missing or invalid dates", () => {
    expect(relativeTime(null, now)).toBe("—");
    expect(relativeTime("not-a-date", now)).toBe("—");
  });
});
