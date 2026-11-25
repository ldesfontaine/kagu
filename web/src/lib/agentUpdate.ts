import { inFlightStates, type ActionRun } from "../api/actions";
import type { Agent, Machine } from "../api/machines";
import type { Translate } from "../i18n/context";

// Où en est la dernière mise à jour (ou le dernier retour arrière) de l'agent
// d'une machine, lue dans ses derniers ordres. Aucune mémoire côté navigateur :
// tout vient du serveur.
export type AgentUpdateState =
  // L'ordre est parti ou accepté : la nouvelle version a trois minutes pour être confirmée.
  | { kind: "pending" }
  | { kind: "confirmed" }
  // L'agent est revenu seul à la version précédente ; target est la version refusée.
  | { kind: "rolled_back"; target: string; cause: "timeout" | "crash" }
  // La remise en état a échoué à son tour.
  | { kind: "rollback_failed" };

const updateKinds: ReadonlySet<string> = new Set(["agent.update", "agent.rollback"]);

// La plus récente des mises à jour et des retours, du plus récent au plus
// ancien (l'ordre de l'API). null : rien de récent à dire, ou un refus qui n'a
// rien changé (l'ordre n'a pas touché l'agent).
export function agentUpdateState(runs: ActionRun[]): AgentUpdateState | null {
  const latest = runs.find((run) => updateKinds.has(run.kind));
  if (latest === undefined) {
    return null;
  }
  if (inFlightStates.has(latest.state)) {
    return { kind: "pending" };
  }
  if (latest.state === "succeeded") {
    return { kind: "confirmed" };
  }
  if (latest.state !== "failed") {
    return null;
  }
  if (latest.reason === "rollback_failed") {
    return { kind: "rollback_failed" };
  }
  if (latest.reason === "rolled_back_timeout" || latest.reason === "rolled_back_crash") {
    const target = typeof latest.params.version === "string" ? latest.params.version : "";
    return { kind: "rolled_back", target, cause: latest.reason === "rolled_back_crash" ? "crash" : "timeout" };
  }
  return null;
}

// Le libellé d'un genre d'ordre (« docker.deploy » → action.kind_docker_deploy).
export function orderKindLabel(t: Translate, kind: string): string {
  return t(`action.kind_${kind.split(".").join("_")}`);
}

// Au-delà, la colonne dit combien d'autres genres manquent ; l'infobulle les
// nomme tous.
const shownMissingKinds = 2;

// Ce que la colonne « Agent » de Machines dit de l'agent, tel que le serveur
// l'a jugé (R-B2-9) : en retard ou non, et ce qu'il ne sait pas faire. Rien
// n'est comparé ici.
export interface AgentStandingText {
  behind: string;
  missing: string;
  missingAll: string;
}

export function agentStandingText(t: Translate, agent: Pick<Agent, "behind" | "missing_kinds">): AgentStandingText {
  const labels = agent.missing_kinds.map((kind) => orderKindLabel(t, kind));
  const shown = labels.slice(0, shownMissingKinds).join(" · ");
  let missing = "";
  if (labels.length > shownMissingKinds) {
    missing = t("machines.agent_missing_more", shown, labels.length - shownMissingKinds);
  } else if (labels.length > 0) {
    missing = t("machines.agent_missing", shown);
  }
  return {
    behind: agent.behind ? t("machines.agent_behind") : "",
    missing,
    missingAll: labels.length > 0 ? t("machines.agent_missing", labels.join(" · ")) : "",
  };
}

// Le nombre d'agents en retard, en tête de Machines (R-B2-13). Un agent
// révoqué (machine archivée) n'est jamais en retard pour le serveur.
export function behindAgents(machines: readonly Machine[]): number {
  return machines.filter((machine) => machine.agent?.behind === true).length;
}
