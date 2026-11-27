import type { AgentAnchors, AnchorKind } from "../api/machines";

// Les ancres de confiance locales : des valeurs que seul l'administrateur de la
// machine pose (à l'installation, ou en root avec « agent trust »). Aucun ordre
// de Kagu ne peut les changer ; sans ancre, l'agent refuse l'ordre qu'elle
// borne. Ce fichier dit comment un écran les montre.

// Le registre du serveur (internal/fact/anchor), dans son ordre : le droit dont
// l'ordre est borné, et ce que l'ancre accepte. Un test relit les noms et les
// droits dans la réponse figée de la fiche d'une machine.
export const anchorKinds = [
  { name: "backup.recipient", right: "backup.produce", max: 2 },
  { name: "backup.guest", right: "backup.produce", max: 32 },
  { name: "restic.target-cert", right: "restic.produce", max: 4 },
] as const;

// Le suffixe des clés du catalogue d'un type : « restic.target-cert » devient
// « restic_target_cert ».
function anchorKey(name: string): string {
  return name.split(/[.-]/).join("_");
}

export function anchorLabelKey(name: string): string {
  return `anchor.label_${anchorKey(name)}`;
}

// Les types d'ancre que les droits portés rendent utiles.
export function anchorKindsFor(rights: readonly string[]): typeof anchorKinds[number][] {
  return anchorKinds.filter((kind) => rights.includes(kind.right));
}

// Les types dont l'ordre est refusé aujourd'hui sur cette machine : le droit
// est coché et l'ancre manque ou ne se lit pas. Vide chez un agent d'avant les
// ancres.
export function blockingAnchors(anchors: AgentAnchors, rights: readonly string[]): AnchorKind[] {
  if (!anchors.reported) {
    return [];
  }
  return anchors.kinds.filter((kind) => kind.state !== "set" && rights.includes(kind.right));
}

// Les raisons d'un ordre refusé par une ancre ont la forme
// « anchor_missing:backup.guest » (aucune posée, illisibles, hors des ancres).
const anchorReasonPattern = /^anchor_(missing|unreadable|outside):([a-z.-]+)$/;

export function anchorOfReason(reason: string): { why: "missing" | "unreadable" | "outside"; name: string } | null {
  const match = anchorReasonPattern.exec(reason);
  if (match === null) {
    return null;
  }
  return { why: match[1] as "missing" | "unreadable" | "outside", name: match[2] ?? "" };
}
