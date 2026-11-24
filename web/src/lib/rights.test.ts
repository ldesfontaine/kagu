import { expect, test } from "vitest";

import { ApiError } from "../api/client";
import type { Agent, Capability, Machine, RightFit } from "../api/machines";
import sessionGolden from "../../../internal/edge/server/testdata/session.golden.json";
import { fixOfRefusal, heldRights, lacksSudo, machineAgentPath, reenrollPath, unfitFor, wantedRightOf } from "./rights";

const t = (key: string, ...args: (string | number)[]) => [key, ...args].join("|");

// La liste fermée du serveur, telle que la session la rend.
const rightNames = sessionGolden.rights;

function agentWith(requested: string[], reported: { name: string; unavailable?: string }[] | null, fit: Record<string, RightFit> = {}): NonNullable<Machine["agent"]> {
  const capability = (name: string): Capability => ({ name, paths: [] });
  return {
    id: "a1",
    version: "v0.0.1",
    enrolled_at: "2026-11-01T10:00:00Z",
    revoked_at: null,
    capabilities: (reported ?? []).map((right) => ({ ...capability(right.name), unavailable: right.unavailable ?? "" })),
    reported_at: reported === null ? null : "2026-11-01T10:00:00Z",
    requested: requested.map(capability),
    capabilities_differ: false,
    server_key_fingerprint: "",
    run_as: null,
    rollback_capable: true, anchors: { reported: false, kinds: [] }, policy_source: "", policy_digest: "",
    fit,
  } satisfies Agent;
}

test("reenrollPath : la fenêtre de la machine, sans droit voulu (T03-03)", () => {
  expect(reenrollPath("m1")).toBe("/machines/m1/reenroller");
});

test("machineAgentPath : l'onglet Agent, avec le droit voulu et le chemin qu'il doit couvrir", () => {
  expect(machineAgentPath("m1")).toBe("/machines/m1/agent");
  expect(machineAgentPath("m1", { name: "agent.update" })).toBe("/machines/m1/agent?droit=agent.update");
  expect(machineAgentPath("m1", { name: "backup.receive", path: "/srv/backups" })).toBe("/machines/m1/agent?droit=backup.receive&chemin=%2Fsrv%2Fbackups");
});

test("wantedRightOf : seul un droit de la liste fermée, hors observe, se demande", () => {
  expect(wantedRightOf(rightNames, new URLSearchParams("droit=docker.deploy"))).toEqual({ name: "docker.deploy", path: "" });
  expect(wantedRightOf(rightNames, new URLSearchParams("droit=backup.receive&chemin=/srv/b"))).toEqual({ name: "backup.receive", path: "/srv/b" });
  expect(wantedRightOf(rightNames, new URLSearchParams("droit=observe"))).toBeNull();
  expect(wantedRightOf(rightNames, new URLSearchParams("droit=rm -rf"))).toBeNull();
  expect(wantedRightOf(rightNames, new URLSearchParams(""))).toBeNull();
});

test("fixOfRefusal : ce que le serveur joint au refus, sans table", () => {
  const fix = { right: "docker.deploy", machine: "m1", command: "sudo x agent grant docker.deploy" };
  expect(fixOfRefusal(new ApiError(409, "deploy.right_missing", { error: "deploy.right_missing", fix }))).toEqual(fix);
  expect(fixOfRefusal(new ApiError(409, "anchor.backup_guest_missing", { fix: { command: "sudo x agent trust list" } }))).toEqual({ command: "sudo x agent trust list" });
  // Un refus sans fix n'en a pas, même si sa clé dit un droit : le front ne le devine pas.
  expect(fixOfRefusal(new ApiError(409, "backup.right_missing"))).toBeNull();
  expect(fixOfRefusal(new ApiError(409, "x", { fix: null }))).toBeNull();
  expect(fixOfRefusal("deploy.right_missing")).toBeNull();
  expect(fixOfRefusal(null)).toBeNull();
});

test("heldRights : ce que l'agent a rapporté, sinon ce que son jeton demandait", () => {
  expect(heldRights(agentWith(["observe", "agent.update"], null)).map((right) => right.name)).toEqual(["observe", "agent.update"]);
  expect(heldRights(agentWith(["observe", "agent.update"], [{ name: "observe" }])).map((right) => right.name)).toEqual(["observe"]);
});

test("unfitFor : une machine convient, ou dit pourquoi pas et où aller, selon le verdict du serveur", () => {
  const ok: RightFit = { state: "ok", reason: "" };
  const missing: RightFit = { state: "missing", reason: "" };
  const fit = { id: "m1", agent: agentWith([], [{ name: "observe" }, { name: "backup.receive" }], { "backup.receive": ok, "docker.deploy": missing }) };
  expect(unfitFor(t, fit, "backup.receive")).toBeNull();

  const noRight = unfitFor(t, fit, "docker.deploy");
  expect(noRight?.reason).toBe("machine.fit_right_missing|machine.capability_docker_deploy");
  expect(noRight?.link).toEqual({ to: "/machines/m1/agent?droit=docker.deploy", label: "machine.grant_right" });

  const noAgent = unfitFor(t, { id: "m2", agent: null }, "backup.receive");
  expect(noAgent?.reason).toBe("machine.fit_no_agent");
  expect(noAgent?.link.to).toBe("/machines/m2/reenroller");

  const revoked = unfitFor(t, { id: "m3", agent: { ...agentWith([], [{ name: "backup.receive" }], { "backup.receive": missing }), revoked_at: "2026-11-01T10:00:00Z" } }, "backup.receive");
  expect(revoked?.reason).toBe("machine.fit_no_agent");

  const unavailable = unfitFor(t, { id: "m4", agent: agentWith([], [{ name: "docker.deploy" }], { "docker.deploy": { state: "unavailable", reason: "docker_denied" } }) }, "docker.deploy");
  expect(unavailable?.reason).toBe("machine.capability_unavailable_docker_denied");
  expect(unavailable?.link.to).toBe("/machines/m4");
});

test("unfitFor ne prend pas les droits demandés pour acquis (X-24) : seul le verdict du serveur compte", () => {
  // Un agent muet dont le jeton demandait le droit : le serveur dit « inconnu »,
  // l'écran le dit aussi, pas « permis ».
  const silent = unfitFor(t, { id: "m5", agent: agentWith(["docker.deploy"], null, { "docker.deploy": { state: "unknown", reason: "" } }) }, "docker.deploy");
  expect(silent?.reason).toBe("machine.fit_right_unknown");
  expect(silent?.link.to).toBe("/machines/m5");
  // Un droit demandé, mais que le serveur dit manquant : il manque.
  const requestedOnly = { id: "m6", agent: agentWith(["docker.deploy"], [{ name: "observe" }], { "docker.deploy": { state: "missing", reason: "" } }) };
  expect(unfitFor(t, requestedOnly, "docker.deploy")?.reason).toBe("machine.fit_right_missing|machine.capability_docker_deploy");
});

test("lacksSudo : un hôte Proxmox, ou un agent qui dit que sudo manque", () => {
  const base = { role: "generic" as const, roles: [], agent: agentWith([], [{ name: "observe" }]) };
  expect(lacksSudo(base)).toBe(false);
  expect(lacksSudo({ ...base, role: "proxmox" })).toBe(true);
  expect(lacksSudo({ ...base, roles: [{ name: "proxmox_ve", version: "8.2" }] })).toBe(true);
  expect(lacksSudo({ ...base, agent: agentWith([], [{ name: "backup.produce", unavailable: "sudo_missing" }]) })).toBe(true);
  expect(lacksSudo({ ...base, agent: null })).toBe(false);
});
