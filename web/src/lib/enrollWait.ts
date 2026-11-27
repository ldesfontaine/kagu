import type { Arrival, Machine } from "../api/machines";
import type { Step } from "./steps";

// Ce que l'assistant attend de l'agent : une machine neuve qui apparaît sous
// son nom, ou la machine existante dont l'agent est remplacé.
// knownIDs : les machines déjà là quand le jeton est né, pour qu'un nom déjà
// pris par une autre ne passe pas pour l'arrivée de la nouvelle.
export type EnrollTarget =
  | { kind: "new"; name: string; knownIDs: string[] }
  | { kind: "reenroll"; machineID: string; previousAgentID: string | null };

// steps : les étapes que join a cochées sur le jeton (R-B1-11), lues du
// serveur ; la tuile les dessine telles quelles.
export type EnrollProgress =
  | { state: "waiting"; steps: Step[] }
  | { state: "expired"; steps: Step[] }
  | { state: "connected"; machine: Machine; steps: Step[] };

function hasActiveAgent(machine: Machine): boolean {
  return machine.agent !== null && machine.agent.revoked_at === null;
}

function hasArrived(target: EnrollTarget, machine: Machine): boolean {
  if (!hasActiveAgent(machine)) {
    return false;
  }
  if (target.kind === "new") {
    return machine.name === target.name && !target.knownIDs.includes(machine.id);
  }
  return machine.id === target.machineID && machine.agent?.id !== target.previousAgentID;
}

// Où en est l'enrôlement, lu dans la liste des machines que le direct relit
// et sur le jeton (arrival, null tant qu'il n'est pas lu). Un jeton expiré
// sans agent ne verra plus rien arriver : l'assistant le dit plutôt que
// d'attendre pour toujours. Le serveur le dit expiré ; l'heure passée le dit
// aussi, faute d'un événement à l'instant où il expire, sauf s'il a servi.
// Un silence de join, même long, n'est pas un échec : seule l'heure du jeton
// l'est.
export function enrollProgress(target: EnrollTarget, machines: readonly Machine[], arrival: Arrival | null, expiresAt: number, now: number): EnrollProgress {
  const steps = arrival?.steps ?? [];
  const machine = machines.find((candidate) => hasArrived(target, candidate));
  if (machine !== undefined) {
    return { state: "connected", machine, steps };
  }
  const expired = arrival?.state === "expired" || (arrival?.state !== "enrolled" && now > expiresAt);
  return expired ? { state: "expired", steps } : { state: "waiting", steps };
}
