import { expect, test } from "vitest";

import type { Agent, Arrival, Machine } from "../api/machines";
import { enrollProgress, type EnrollTarget } from "./enrollWait";

function agent(id: string, revokedAt: string | null = null): Agent {
  return { id, revoked_at: revokedAt } as Agent;
}

function machine(id: string, name: string, agentOf: Agent | null): Machine {
  return { id, name, agent: agentOf } as Machine;
}

const expiresAt = Date.parse("2026-10-31T12:00:00Z");
const before = expiresAt - 60_000;
const after = expiresAt + 1_000;

const added: EnrollTarget = { kind: "new", name: "vps-1", knownIDs: ["m1"] };
const reenrolled: EnrollTarget = { kind: "reenroll", machineID: "m1", previousAgentID: "a1" };

test("machine neuve : attend tant qu'aucune machine de ce nom n'a d'agent actif", () => {
  expect(enrollProgress(added, [], null, expiresAt, before)).toEqual({ state: "waiting", steps: [] });
  expect(enrollProgress(added, [machine("m2", "vps-1", null)], null, expiresAt, before)).toEqual({ state: "waiting", steps: [] });
  expect(enrollProgress(added, [machine("m2", "vps-1", agent("a2", "2026-10-31T10:00:00Z"))], null, expiresAt, before)).toEqual({ state: "waiting", steps: [] });
});

test("machine neuve : connectée dès que la machine de ce nom a un agent actif", () => {
  const arrived = machine("m2", "vps-1", agent("a2"));
  expect(enrollProgress(added, [machine("m1", "autre", agent("a1")), arrived], null, expiresAt, before)).toEqual({ state: "connected", machine: arrived, steps: [] });
});

test("machine neuve : une machine déjà connue sous ce nom n'est pas l'arrivée", () => {
  expect(enrollProgress(added, [machine("m1", "vps-1", agent("a1"))], null, expiresAt, before)).toEqual({ state: "waiting", steps: [] });
});

test("ré-enrôlement : attend l'ancien agent, connecté dès qu'un autre est actif", () => {
  expect(enrollProgress(reenrolled, [machine("m1", "vps-1", agent("a1"))], null, expiresAt, before)).toEqual({ state: "waiting", steps: [] });
  const replaced = machine("m1", "vps-1", agent("a2"));
  expect(enrollProgress(reenrolled, [replaced], null, expiresAt, before)).toEqual({ state: "connected", machine: replaced, steps: [] });
});

test("ré-enrôlement d'une machine sans agent actif : le premier agent actif est l'arrivée", () => {
  const revoked: EnrollTarget = { kind: "reenroll", machineID: "m1", previousAgentID: "a1" };
  expect(enrollProgress(revoked, [machine("m1", "vps-1", agent("a1", "2026-10-31T10:00:00Z"))], null, expiresAt, before)).toEqual({ state: "waiting", steps: [] });
  const never: EnrollTarget = { kind: "reenroll", machineID: "m1", previousAgentID: null };
  const first = machine("m1", "vps-1", agent("a9"));
  expect(enrollProgress(never, [first], null, expiresAt, before)).toEqual({ state: "connected", machine: first, steps: [] });
});

test("jeton expiré : l'attente le dit, sauf si l'agent est arrivé à temps", () => {
  expect(enrollProgress(added, [], null, expiresAt, after)).toEqual({ state: "expired", steps: [] });
  const arrived = machine("m2", "vps-1", agent("a2"));
  expect(enrollProgress(added, [arrived], null, expiresAt, after)).toEqual({ state: "connected", machine: arrived, steps: [] });
});

const firstContact = { key: "step.enroll.system", state: "done", detail: "Debian 12, amd64", at: "2026-10-31T11:00:00Z" } as const;

test("R-B1-11 : l'attente porte les étapes lues sur le jeton, telles que le serveur les rend", () => {
  const arrival: Arrival = { state: "pending", expires_at: "2026-10-31T12:00:00Z", steps: [firstContact] };
  expect(enrollProgress(added, [], arrival, expiresAt, before)).toEqual({ state: "waiting", steps: [firstContact] });
  const refused = { key: "step.enroll.enrolled", state: "failed", detail: "token_expired", at: "2026-10-31T12:05:00Z" } as const;
  expect(enrollProgress(added, [], { ...arrival, state: "expired", steps: [firstContact, refused] }, expiresAt, before)).toEqual({ state: "expired", steps: [firstContact, refused] });
});

test("un silence de join n'est pas un échec : seule l'heure du jeton l'est, et un jeton servi n'expire plus", () => {
  // Premier contact, puis rien pendant quinze minutes : l'attente reste.
  const quiet = expiresAt - 30 * 60_000;
  const arrival: Arrival = { state: "pending", expires_at: "2026-10-31T12:00:00Z", steps: [firstContact] };
  expect(enrollProgress(added, [], arrival, expiresAt, quiet).state).toBe("waiting");
  expect(enrollProgress(added, [], { ...arrival, state: "enrolled" }, expiresAt, after).state).toBe("waiting");
});
