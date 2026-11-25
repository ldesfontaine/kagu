import { expect, test } from "vitest";

import type { Agent, Machine } from "../api/machines";
import { kindFix } from "./machineKind";

const noProxmox: Machine["proxmox"] = { declared: false, guests: 0, last_error: "", backup_blind: false, node: "", cluster: null, guest_list: [], hosted: null };

function machine(over: Partial<Machine> = {}): Machine {
  const agent = { version: "v0.5.0", revoked_at: null, behind: false } as Agent;
  return { id: "m", name: "m", agent, kind: "unknown", kind_override: "", role: "generic", roles: [], proxmox: noProxmox, ...over } as Machine;
}

test("un type connu ou corrigé à la main n'a rien à résoudre", () => {
  expect(kindFix(machine({ kind: "vm" }), [])).toBeNull();
  expect(kindFix(machine({ kind_override: "vps" }), [])).toBeNull();
});

test("une machine archivée n'a rien à résoudre", () => {
  const revoked = { version: "v0.2.0", revoked_at: "2026-02-01T00:00:00Z", behind: false } as Agent;
  expect(kindFix(machine({ agent: revoked }), [])).toBeNull();
});

test("sans agent, on ré-enrôle", () => {
  expect(kindFix(machine({ agent: null }), [])).toEqual({ action: "reenroll", to: "/machines/m/reenroller" });
});

test("un agent que le serveur dit en retard se met à jour d'abord : il ne rapporte pas le type", () => {
  const old = { version: "v0.2.0", revoked_at: null, behind: true } as Agent;
  expect(kindFix(machine({ agent: old }), [])).toEqual({ action: "update_agent", to: "/machines/m/agent" });
});

test("un hôte Proxmox reconnu mais non déclaré, sur une autre machine, se déclare", () => {
  const host = machine({ id: "pve", roles: [{ name: "proxmox_ve", version: "8.2" }], kind: "physical" });
  expect(kindFix(machine(), [machine(), host])).toEqual({ action: "declare_host", to: "/machines/pve/proxmox" });
  const declared = machine({ id: "pve", roles: host.roles, proxmox: { ...noProxmox, declared: true } });
  expect(kindFix(machine(), [machine(), declared])?.action).toBe("correct");
});

test("sinon, on corrige à la main", () => {
  expect(kindFix(machine(), [machine()])).toEqual({ action: "correct", to: "/machines/m/emplacement" });
});
