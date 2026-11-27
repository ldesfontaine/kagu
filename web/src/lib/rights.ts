import type { ApiError, RefusalFix } from "../api/client";
import type { AgentRights, Capability, Machine, RightState } from "../api/machines";
import type { Translate } from "../i18n/context";
import { detectedProxmox } from "./proxmox";
import type { Tone } from "./tone";
import { alwaysGranted, capabilityLabelKey, describeUnavailable } from "./machines";

// Les droits d'un agent manquent ici ou là ; ce fichier dit comment un écran
// le sait, et où il mène l'opérateur : la ligne grant à lancer en root sur la
// machine, que l'onglet Agent de sa fiche montre pour le droit voulu.

// Le ton de la pastille d'un état de droit : le serveur juge (agentpolicy.Fit),
// la table ne fait que traduire.
export const rightTones: Record<RightState, Tone> = { ok: "ok", missing: "danger", unavailable: "warn", unknown: "neutral" };

// Un droit voulu : son nom et, pour un droit borné, le chemin qu'il doit
// couvrir (une indication : la ligne du serveur n'en porte pas).
interface WantedRight {
  name: string;
  path: string;
}

// Le nom d'un jeu, et sa phrase : ce qu'il donne, ou ce qu'il coûte
// (R-A3-13). Les mêmes sur l'onglet Droits, au choix d'un jeu à l'ajout d'une
// machine et dans le terminal de setup.
export const rightsSetLabels: Record<AgentRights["set"], string> = {
  observe: "rights.observe",
  manage: "rights.manage",
  root: "rights.root",
  "": "rights.custom",
  refused: "rights.refused",
};
export const rightsSetPhrases: Record<AgentRights["set"], string> = {
  observe: "rights.observe_hint",
  manage: "rights.manage_risk",
  root: "rights.root_risk",
  "": "rights.custom_hint",
  refused: "rights.refused_hint",
};

// L'adresse de la fenêtre « Ré-enrôler » d'une machine : changer la clé de
// son agent, ou en installer un.
export function reenrollPath(machineID: string): string {
  return `/machines/${machineID}/reenroller`;
}

// L'onglet Agent de la fiche d'une machine ; avec un droit voulu, il montre
// la ligne qui le pose (une liste d'actions ne porte qu'un lien).
export function machineAgentPath(machineID: string, wanted?: { name: string; path?: string | undefined }): string {
  const base = `/machines/${machineID}/agent`;
  if (wanted === undefined) {
    return base;
  }
  const query = new URLSearchParams({ droit: wanted.name });
  if (wanted.path !== undefined && wanted.path !== "") {
    query.set("chemin", wanted.path);
  }
  return `${base}?${query.toString()}`;
}

// Le droit que l'adresse demande ; rien si le nom n'est pas un droit de la
// liste fermée de la session (observe est toujours accordé).
export function wantedRightOf(rightNames: readonly string[], search: URLSearchParams): WantedRight | null {
  const name = search.get("droit");
  const known = rightNames.find((candidate) => candidate === name && candidate !== alwaysGranted);
  return known === undefined ? null : { name: known, path: search.get("chemin") ?? "" };
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
    return { reason: t("machine.fit_right_missing", t(capabilityLabelKey(right))), link: { to: machineAgentPath(machine.id, { name: right }), label: t("machine.grant_right") } };
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

// On tient pour acquis que la machine n'a pas sudo : un hôte Proxmox n'en a pas
// (Debian sans sudo). Les blocs à coller se proposent alors en root, sans sudo.
export function lacksSudo(machine: Pick<Machine, "role" | "roles">): boolean {
  return machine.role === "proxmox" || detectedProxmox(machine) !== null;
}
