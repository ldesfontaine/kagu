import { describe, expect, it } from "vitest";

import type { ActionRun } from "../api/actions";
import type { Machine } from "../api/machines";
import { agentStandingText, agentUpdateState, behindAgents } from "./agentUpdate";

function run(overrides: Partial<ActionRun>): ActionRun {
  return {
    id: "run1",
    kind: "agent.update",
    params: { version: "v0.0.2" },
    machine_id: "m1",
    machine_name: "vps",
    agent_id: "a1",
    service_id: null,
    state: "accepted",
    reason: "",
    seq: 1,
    requested_by: "operator:5e55105e55105e55",
    requested_by_label: "lucas",
    requested_at: "2026-10-29T10:00:00Z",
    not_after: "2026-10-29T10:02:00Z",
    finished_at: null,
    output: [],
    ...overrides,
  };
}

describe("agentUpdateState", () => {
  it("says nothing without any update order", () => {
    expect(agentUpdateState([])).toBeNull();
    expect(agentUpdateState([run({ kind: "agent.ping", state: "succeeded" })])).toBeNull();
  });

  it("waits for the confirmation while the order is in flight", () => {
    for (const state of ["queued", "sent", "accepted"] as const) {
      expect(agentUpdateState([run({ state })])).toEqual({ kind: "pending" });
    }
  });

  it("confirms a succeeded update or rollback", () => {
    expect(agentUpdateState([run({ state: "succeeded" })])).toEqual({ kind: "confirmed" });
    expect(agentUpdateState([run({ kind: "agent.rollback", params: {}, state: "succeeded" })])).toEqual({ kind: "confirmed" });
  });

  it("reads the automatic return with its cause and the refused version", () => {
    expect(agentUpdateState([run({ state: "failed", reason: "rolled_back_timeout" })])).toEqual({ kind: "rolled_back", target: "v0.0.2", cause: "timeout" });
    expect(agentUpdateState([run({ state: "failed", reason: "rolled_back_crash" })])).toEqual({ kind: "rolled_back", target: "v0.0.2", cause: "crash" });
  });

  it("flags a failed recovery loudly", () => {
    expect(agentUpdateState([run({ state: "failed", reason: "rollback_failed" })])).toEqual({ kind: "rollback_failed" });
  });

  it("ignores a refusal that changed nothing, and only reads the latest order", () => {
    expect(agentUpdateState([run({ state: "refused", reason: "guard_missing" })])).toBeNull();
    const runs = [run({ id: "new", state: "succeeded" }), run({ id: "old", state: "failed", reason: "rolled_back_crash" })];
    expect(agentUpdateState(runs)).toEqual({ kind: "confirmed" });
  });
});

// Un traducteur qui rend la clé et ses arguments : le test lit ce que la
// colonne choisit de dire, pas le catalogue.
const t = (key: string, ...args: (string | number)[]) => [key, ...args].join(":");

describe("agentStandingText", () => {
  it("says an older agent needs an update, and what it cannot do", () => {
    const standing = agentStandingText(t, { behind: true, missing_kinds: ["docker.deploy"] });
    expect(standing.behind).toBe("machines.agent_behind");
    expect(standing.missing).toBe("machines.agent_missing:action.kind_docker_deploy");
  });

  it("never says it for an agent the server finds up to date", () => {
    expect(agentStandingText(t, { behind: false, missing_kinds: [] })).toEqual({ behind: "", missing: "", missingAll: "" });
  });

  it("names two kinds, counts the others, and names them all in the tooltip", () => {
    const standing = agentStandingText(t, { behind: true, missing_kinds: ["docker.deploy", "docker.update", "agent.ping", "backup.receive"] });
    expect(standing.missing).toBe("machines.agent_missing_more:action.kind_docker_deploy · action.kind_docker_update:2");
    expect(standing.missingAll).toBe("machines.agent_missing:action.kind_docker_deploy · action.kind_docker_update · action.kind_agent_ping · action.kind_backup_receive");
  });
});

describe("behindAgents", () => {
  it("counts the agents the server says are behind", () => {
    const machines = [{ agent: { behind: true } }, { agent: { behind: false } }, { agent: null }, { agent: { behind: true } }] as Machine[];
    expect(behindAgents(machines)).toBe(2);
  });
});
