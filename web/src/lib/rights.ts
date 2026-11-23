import type { ApiError, RefusalFix } from "../api/client";
import type { Capability, Machine } from "../api/machines";
import type { Translate } from "../i18n/context";
import { detectedProxmox } from "./proxmox";
import { alwaysGranted, capabilityLabelKey, describeUnavailable, type RightsValues } from "./machines";

// Les droits d'un agent manquent ici ou là ; ce fichier dit comment un écran
// le sait, et où il mène l'opérateur : le ré-enrôlement, déjà coché du droit.

// Un droit voulu : son nom et, pour un droit borné, le chemin à ajouter.
interface WantedRight {
  name: string;
  path: string;
}

// L'adresse de la fenêtre « Ré-enrôler » d'une machine, avec le droit à y
// cocher d'avance.
export function reenrollPath(machineID: string, wanted?: { name: string; path?: string | undefined }): string {
  const base = `/machines/${machineID}/reenroller`;
  if (wanted === undefined) {
    return base;
  }
  const query = new URLSearchParams({ droit: wanted.name });
  if (wanted.path !== undefined && wanted.path !== "") {
    query.set("chemin", wanted.path);
  }
  return `${base}?${query.toString()}`;
}

// Le droit que l'adresse demande de cocher ; rien si le nom n'est pas un droit
// de la liste fermée de la session (observe est toujours accordé, il n'a pas
// de case).
export function wantedRightOf(rightNames: readonly string[], search: URLSearchParams): WantedRight | null {
  const name = search.get("droit");
  const known = rightNames.find((candidate) => candidate === name && candidate !== alwaysGranted);
  return known === undefined ? null : { name: known, path: search.get("chemin") ?? "" };
}

// Les valeurs du formulaire des droits avec le droit voulu coché ; son chemin
// s'ajoute à ceux qui y sont, sans doublon.
export function withWantedRight(values: RightsValues, wanted: WantedRight | null): RightsValues {
  if (wanted === null) {
    return values;
  }
  const rights = values.rights.includes(wanted.name) ? values.rights : [...values.rights, wanted.name];
  return {
    ...values,
    rights,
    backupPath: wanted.name === "backup.receive" ? addPath(values.backupPath, wanted.path) : values.backupPath,
    writePaths: wanted.name === "files.write" ? addPath(values.writePaths, wanted.path) : values.writePaths,
    // restic.target n'a qu'un dossier : le voulu remplace l'ancien.
    resticPath: wanted.name === "restic.target" && wanted.path !== "" ? wanted.path : values.resticPath,
  };
}

function addPath(paths: string, path: string): string {
  const kept = paths.split(",").map((entry) => entry.trim()).filter((entry) => entry !== "");
  if (path === "" || kept.includes(path)) {
    return kept.join(", ");
  }
  return [...kept, path].join(", ");
}

// Les droits que l'agent a : ce qu'il a rapporté, sinon ce que son jeton
// demandait (il n'a pas encore parlé).
export function heldRights(agent: NonNullable<Machine["agent"]>): Capability[] {
  return agent.reported_at === null ? agent.requested : agent.capabilities;
}

// Une machine ne convient pas à un geste : pourquoi, et où aller pour y
// remédier.
export interface Unfit {
  reason: string;
  link: { to: string; label: string };
}

// Dit si la machine peut faire ce que demande right (null : il suffit d'un
// agent actif), ou pourquoi elle ne le peut pas, selon le verdict que le
// serveur rend par droit. Un droit coché que le compte de l'agent ne peut pas
// exercer ne convient pas non plus : la raison est celle que la fiche donne.
// Un agent qui n'a pas encore rapporté ses droits ne convient pas tant que le
// serveur ne sait pas : ce que son jeton demandait n'y change rien.
export function unfitFor(t: Translate, machine: Pick<Machine, "id" | "agent">, right: string | null): Unfit | null {
  const agent = machine.agent;
  if (agent === null || agent.revoked_at !== null) {
    return { reason: t("machine.fit_no_agent"), link: { to: reenrollPath(machine.id), label: t("machine.fit_enroll") } };
  }
  if (right === null) {
    return null;
  }
  const fit = agent.fit[right];
  if (fit === undefined || fit.state === "missing") {
    return { reason: t("machine.fit_right_missing", t(capabilityLabelKey(right))), link: { to: reenrollPath(machine.id, { name: right }), label: t("machine.reenroll_with_right") } };
  }
  if (fit.state === "unavailable") {
    return { reason: describeUnavailable(t, fit.reason, agent.run_as), link: { to: `/machines/${machine.id}`, label: t("machine.fit_open") } };
  }
  if (fit.state === "unknown") {
    return { reason: t("machine.fit_right_unknown"), link: { to: `/machines/${machine.id}`, label: t("machine.fit_open") } };
  }
  return null;
}

// Ce que le serveur joint à un refus pour le lever (fix) : le droit et sa
// machine, ou la commande d'une ancre. null pour un refus qui n'en porte pas.
export function fixOfRefusal(error: ApiError | string | null | undefined): RefusalFix | null {
  if (error === null || error === undefined || typeof error === "string") {
    return null;
  }
  const payload = error.payload;
  if (typeof payload !== "object" || payload === null || !("fix" in payload) || typeof payload.fix !== "object" || payload.fix === null) {
    return null;
  }
  return payload.fix as RefusalFix;
}

// La machine n'a pas sudo, ou on le tient pour acquis : un hôte Proxmox n'en a pas
// (Debian sans sudo), et l'agent le dit quand un droit en dépend (sudo_missing).
// Les blocs à coller se proposent alors en root, sans sudo.
export function lacksSudo(machine: Pick<Machine, "role" | "roles" | "agent">): boolean {
  const reportsMissing = machine.agent?.capabilities.some((capability) => capability.unavailable === "sudo_missing") ?? false;
  return machine.role === "proxmox" || detectedProxmox(machine) !== null || reportsMissing;
}
