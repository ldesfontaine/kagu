import { expect, test } from "vitest";

import type { ActionState } from "../api/actions";
import { stateTones } from "./actions";

const allStates: ActionState[] = ["queued", "sent", "accepted", "refused", "succeeded", "failed", "expired"];

test("every action state has a tone", () => {
  expect(Object.keys(stateTones).sort()).toEqual([...allStates].sort());
});

test("a queued order is neutral", () => {
  expect(stateTones.queued).toBe("neutral");
});
