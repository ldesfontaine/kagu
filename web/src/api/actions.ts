import { useResource, type Resource } from "../hooks/useResource";
import { api, segment, type RefusalFix } from "./client";
import { route } from "./routes";

// Les ordres envoyés aux agents (ping, mise à jour, sauvegarde, déploiement) et ce qu'ils
// deviennent. Sujet du direct : « actions », que topicsOf devine du chemin.
// Le genre, l'état et la raison se traduisent sous action.*.

export type ActionState = "queued" | "sent" | "accepted" | "refused" | "succeeded" | "failed" | "expired";

// Un ordre encore en route : un second pour le même service ne part pas avant lui.
export const inFlightStates: ReadonlySet<ActionState> = new Set<ActionState>(["queued", "sent", "accepted"]);

export interface RunLine {
  at: string;
  stream: string;
  line: string;
}

export interface ActionRun {
  id: string;
  // agent.ping : la liste fermée du protocole.
  kind: string;
  // Sans secret ; {} pour un ordre qui n'en prend pas.
  params: Record<string, unknown>;
  // null : la machine ou l'agent a été supprimé depuis, le run reste.
  machine_id: string | null;
  machine_name: string;
  agent_id: string | null;
  // Le service déclaré que vise un ordre de déploiement ; null sinon.
  service_id: string | null;
  state: ActionState;
  // La raison de l'agent, ou « undelivered » ; vide sinon.
  reason: string;
  seq: number;
  // L'acteur enregistré et signé (la session d'un opérateur) ; l'écran
  // montre requested_by_label, le compte ou le nom du jeton, vide sans libellé.
  requested_by: string;
  requested_by_label: string;
  requested_at: string;
  not_after: string;
  finished_at: string | null;
  output: RunLine[];
  // Ce qui lève le refus de l'ordre par un droit ou une ancre ; absent sinon.
  fix?: RefusalFix;
}

export interface ActionsResponse {
  runs: ActionRun[];
}

// La clé qui signe les ordres : ce que chaque agent épingle à l'enrôlement.
export interface ServerKey {
  public_key: string;
  fingerprint: string;
  // La clé précédente, le temps d'une rotation : un agent resté dessus la
  // garde jusqu'à ce que root colle trust_line. null hors rotation.
  previous_fingerprint: string | null;
  // La ligne « trust set » que root colle sur une machine qui accepte une
  // autre clé, rendue par le serveur.
  trust_line: string;
}

// Les derniers ordres d'une machine, ce que sa fiche montre.
const machineActionsLimit = 10;

function actionsPath(machineID: string): string {
  return `/api/actions?machine=${segment(machineID)}&limit=${machineActionsLimit}`;
}

export function useMachineActions(machineID: string): Resource<ActionsResponse> {
  return useResource<ActionsResponse>(() => actionsPath(machineID));
}

// Où en est la clé épinglée par rapport à celle du serveur ; « current »
// tant que la clé du serveur n'est pas lue.
export function pinnedKeyState(key: ServerKey | null, pinned: string): "current" | "previous" | "differs" {
  if (key === null || key.fingerprint === pinned) return "current";
  if (key.previous_fingerprint === pinned) return "previous";
  return "differs";
}

export function useServerKey(): Resource<ServerKey> {
  return useResource<ServerKey>("/api/agents/server-key");
}

// L'ordre agent.ping : écrit et journalisé avant de partir ; la réponse de
// l'agent arrive par le direct.
export async function pingAgent(machineID: string): Promise<ActionRun> {
  return api.send<ActionRun>(route("POST /api/machines/{id}/actions/ping", { id: machineID }));
}

// « Demander ce droit à la machine » (ARB-1) : l'ordre right.request part
// sans jugement d'avance ; l'agent le refuse et le note pour « grant
// --pending ». value : un producteur, seulement pour backup.produce.
export async function requestRight(machineID: string, right: string, value = ""): Promise<ActionRun> {
  return api.send<ActionRun>(route("POST /api/machines/{id}/actions/request-right", { id: machineID }), { right, value });
}

// Ce que la fiche d'une machine propose à son agent : la version du serveur,
// ou pourquoi pas. reason est vide quand la mise à jour est disponible, sauf
// « right_unavailable » : le compte de l'agent ne peut pas l'exercer, l'offre
// reste faite et c'est l'agent qui refusera. « same_version » dit qu'il n'y a
// rien à dire.
export interface AgentUpdateOffer {
  current: string;
  target: string;
  arch: string;
  available: boolean;
  reason: string;
}

function agentUpdatePath(machineID: string): string {
  return `/api/machines/${segment(machineID)}/agent-update`;
}

// Le plan des mises à jour d'agents : la version du serveur ; une version
// importée plus récente, que root n'a pas installée, et la ligne qui
// l'installe (vides sinon) ; la mise à jour en vol ; et, par machine, où en
// est son agent, tel que le serveur l'a jugé.
export interface AgentUpdatePlan {
  target: string;
  imported_ahead: string;
  upgrade_line: string;
  in_progress: AgentUpdateInProgress | null;
  machines: AgentUpdatePlanEntry[];
}

interface AgentUpdateInProgress {
  run_id: string;
  kind: string;
  machine_id: string | null;
  machine_name: string;
  requested_at: string;
}

interface AgentUpdatePlanEntry {
  machine_id: string;
  name: string;
  version: string;
  target: string;
  up_to_date: boolean;
  // Plus ancien que le serveur, et les genres d'ordres qu'il ne reçoit pas.
  behind: boolean;
  missing_kinds: string[];
  rollback_capable: boolean;
  online: boolean;
  update_last: boolean;
  // Une raison de la fiche (machine.agent_update_reason_*) ; vide si l'ordre
  // peut partir, ou si la machine est à jour.
  blocked_reason: string;
  // Le rang recommandé ; null quand rien n'est à faire ou ne peut partir.
  order: number | null;
}

export function useAgentUpdatePlan(): Resource<AgentUpdatePlan> {
  return useResource<AgentUpdatePlan>("/api/agent-updates");
}

export function useAgentUpdateOffer(machineID: string): Resource<AgentUpdateOffer> {
  return useResource<AgentUpdateOffer>(() => agentUpdatePath(machineID));
}

// L'ordre agent.update : le serveur revérifie la version importée, l'agent la
// revérifie, puis redémarre. L'ordre est fini quand il revient avec la
// nouvelle version.
export async function updateAgent(machineID: string): Promise<ActionRun> {
  return api.send<ActionRun>(route("POST /api/machines/{id}/actions/update-agent", { id: machineID }));
}

// L'ordre agent.rollback : l'agent rebascule sur la version d'avant, l'éprouve
// et redémarre. Confirmé ou annulé comme une mise à jour.
export async function rollbackAgent(machineID: string): Promise<ActionRun> {
  return api.send<ActionRun>(route("POST /api/machines/{id}/actions/rollback-agent", { id: machineID }));
}

// Pose ou retire « à mettre à jour en dernier » sur la machine (l'opérateur
// seul : la route n'est ouverte à aucun jeton).
export async function setUpdateLast(machineID: string, updateLast: boolean): Promise<void> {
  await api.send(route("PUT /api/machines/{id}/update-last", { id: machineID }), { update_last: updateLast });
}

// Les lignes à coller sur une machine dont l'agent n'a pas encore le retour
// arrière automatique : les mêmes pour toutes, avec la version de ce serveur.
export interface AgentMigration {
  version: string;
  // Le bloc d'un compte non root qui a sudo, et celui de root, sans sudo.
  commands: string;
  root_commands: string;
}

export function useAgentMigration(): Resource<AgentMigration> {
  return useResource<AgentMigration>("/api/agent-migration");
}
