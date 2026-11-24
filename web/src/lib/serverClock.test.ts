import { describe, expect, it } from "vitest";

import { clockOffset, serverClock } from "./serverClock";
import { formatWhen } from "./time";

describe("serverClock", () => {
  it("E02-21 : dit l'heure du serveur reculé de 5 min, pas celle du navigateur, et la fait avancer", () => {
    const receivedAt = Date.parse("2026-11-24T14:32:10Z");
    const offset = clockOffset("2026-11-24T14:27:10Z", receivedAt);
    expect(offset).toBe(-5 * 60 * 1000);
    expect(serverClock(offset, receivedAt)).toBe(formatWhen("2026-11-24T14:27:10Z", receivedAt));
    expect(serverClock(offset, receivedAt)).not.toBe(formatWhen("2026-11-24T14:32:10Z", receivedAt));
    const later = receivedAt + 60 * 1000;
    expect(serverClock(offset, later)).toBe(formatWhen("2026-11-24T14:28:10Z", later));
  });
});
