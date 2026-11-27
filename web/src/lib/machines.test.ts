import { expect, test } from "vitest";

import type { Machine } from "../api/machines";
import type { Translate } from "../i18n/context";
import { canConfirmDeletion, isArchived, liveMachines, capabilityLabelKey, describeAccount, describeCapability, describeUnavailable, emptyMachineForm, isMachineFormModified, joinPasteText, kindsByID, machineOption, machineSeen, machinesSubtitle, unavailableRights } from "./machines";

const t: Translate = (key, ...args) => [key, ...args].join(":");

test("machinesSubtitle dit l'accueil sans machine, puis le compte et celles en ligne", () => {
  expect(machinesSubtitle(t, 0, 0)).toBe("overview.subtitle");
  expect(machinesSubtitle(t, 1, 1)).toBe("machines.subtitle_one:1");
  expect(machinesSubtitle(t, 4, 3)).toBe("machines.subtitle:4:3");
});

test("machineSeen : en ligne, vue à l'instant ; hors ligne, depuis son dernier signal", () => {
  const now = Date.parse("2026-09-12T12:00:00Z");
  expect(machineSeen(t, { online: true, last_seen_at: "2026-09-12T11:50:00Z" }, now)).toBe("machine.seen_now");
  expect(machineSeen(t, { online: false, last_seen_at: "2026-09-12T11:59:48Z" }, now)).toBe("machine.seen_ago:time.seconds:12");
  expect(machineSeen(t, { online: false, last_seen_at: null }, now)).toBe("machine.never_seen");
});

test("la clé d'un libellé remplace le point", () => {
  expect(capabilityLabelKey("files.write")).toBe("machine.capability_files_write");
  expect(describeCapability(t, { name: "files.write", paths: ["/a", "/b"] })).toBe("machine.right_with_paths:machine.capability_files_write:/a, /b");
  expect(describeCapability(t, { name: "observe", paths: [] })).toBe("machine.capability_observe");
});

test("describeAccount : le nom et l'uid, l'uid seul sans nom, rien tant que l'agent n'a rien dit", () => {
  expect(describeAccount({ uid: 998, name: "kagu-agent" })).toBe("kagu-agent (998)");
  expect(describeAccount({ uid: 0, name: "root" })).toBe("root (0)");
  expect(describeAccount({ uid: 4000, name: "" })).toBe("4000");
  expect(describeAccount(null)).toBeNull();
});

test("describeUnavailable : une phrase par raison, celle d'un dossier refusé nomme le compte, ou change sous root", () => {
  expect(describeUnavailable(t, "docker_denied", null)).toBe("machine.capability_unavailable_docker_denied");
  expect(describeUnavailable(t, "gate_denied", null)).toBe("machine.capability_unavailable_gate_denied");
  expect(describeUnavailable(t, "path_unwritable", { uid: 998, name: "svc" })).toBe("machine.capability_unavailable_path_unwritable");
  expect(describeUnavailable(t, "path_denied", { uid: 998, name: "svc" })).toBe("machine.capability_unavailable_path_denied:svc");
  expect(describeUnavailable(t, "path_denied", { uid: 4000, name: "" })).toBe("machine.capability_unavailable_path_denied:4000");
  expect(describeUnavailable(t, "path_denied", { uid: 0, name: "root" })).toBe("machine.capability_unavailable_path_denied_root");
});

test("unavailableRights : seuls les droits que le compte ne peut pas exercer, avec leur raison", () => {
  const agent = {
    run_as: { uid: 998, name: "svc" },
    capabilities: [
      { name: "observe", paths: [], unavailable: "", until: null },
      { name: "docker.deploy", paths: [], unavailable: "docker_denied", until: null },
      { name: "backup.receive", paths: ["/srv/backups"], unavailable: "path_denied", until: null },
      { name: "agent.update", paths: [], unavailable: "", until: null },
    ],
  };
  expect(unavailableRights(t, agent)).toEqual([
    "machine.capability_unavailable_item:machine.capability_docker_deploy:machine.capability_unavailable_docker_denied",
    "machine.capability_unavailable_item:machine.right_with_paths:machine.capability_backup_receive:/srv/backups:machine.capability_unavailable_path_denied:svc",
  ]);
  expect(unavailableRights(t, { run_as: null, capabilities: [{ name: "observe", paths: [], unavailable: "", until: null }] })).toEqual([]);
});

test("isMachineFormModified : le formulaire neuf est propre, un nom, un rôle ou un jeu choisi ne l'est plus", () => {
  expect(isMachineFormModified(emptyMachineForm)).toBe(false);
  expect(isMachineFormModified({ ...emptyMachineForm, name: "  " })).toBe(false);
  expect(isMachineFormModified({ ...emptyMachineForm, name: "vps-1" })).toBe(true);
  expect(isMachineFormModified({ ...emptyMachineForm, role: "docker" })).toBe(true);
  expect(isMachineFormModified({ ...emptyMachineForm, set: "manage" })).toBe(true);
});

// B1 §3 : « Copier » prend deux lignes, la commande puis le jeton.
test("joinPasteText : la commande, puis le jeton, chacun sur sa ligne", () => {
  expect(joinPasteText({ command: "curl … | sudo sh -s -- join --rights manage", token: "kg_secret" })).toBe("curl … | sudo sh -s -- join --rights manage\nkg_secret\n");
});

const archivedAgent = { agent: { revoked_at: "2026-10-31T10:00:00Z" } } as Pick<Machine, "agent">;
const activeAgent = { agent: { revoked_at: null } } as Pick<Machine, "agent">;

test("une machine est archivée quand son agent est révoqué, pas avant", () => {
  expect(isArchived(archivedAgent)).toBe(true);
  expect(isArchived(activeAgent)).toBe(false);
  expect(isArchived({ agent: null })).toBe(false);
});

test("les machines attendues sont les non archivées : l'archive reste dans la liste mais ne compte pas", () => {
  expect(liveMachines([archivedAgent, activeAgent, { agent: null }])).toEqual([activeAgent, { agent: null }]);
});

test("garder l'historique part tout de suite ; effacer attend le nom tapé tel quel", () => {
  expect(canConfirmDeletion("vps-paris-1", "", true)).toBe(true);
  expect(canConfirmDeletion("vps-paris-1", "", false)).toBe(false);
  expect(canConfirmDeletion("vps-paris-1", "vps-paris", false)).toBe(false);
  expect(canConfirmDeletion("vps-paris-1", "VPS-PARIS-1", false)).toBe(false);
  expect(canConfirmDeletion("vps-paris-1", "vps-paris-1", false)).toBe(true);
});

test("l'option d'une machine porte son type en discret, rien sans type", () => {
  expect(machineOption(t, { id: "m", name: "web", kind: "lxc" })).toEqual({ value: "m", label: "web", hint: "machine.kind_lxc" });
  expect(machineOption(t, { id: "m", name: "web" }).hint).toBeUndefined();
});

test("le type de chaque machine se retrouve par identifiant", () => {
  expect(kindsByID([{ id: "a", kind: "vm" }]).get("a")).toBe("vm");
});
