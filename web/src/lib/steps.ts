import type { IconName } from "../components/Icon";
import type { Tone } from "./tone";

// Une étape cochée d'un geste suivi, telle que le serveur la garde
// (gesture_steps) : la clé est celle du catalogue, le détail du texte venu de
// l'agent, déjà nettoyé.
export type StepState = "running" | "done" | "failed" | "skipped";

export interface Step {
  key: string;
  state: StepState;
  detail?: string;
  at: string;
}

// Le ton et le signe d'une étape selon son état ; le terminal (step.Print)
// imprime ✓, ✗, – ou … pour les mêmes états.
export const stepTones: Record<StepState, Tone> = {
  running: "accent",
  done: "ok",
  failed: "danger",
  skipped: "neutral",
};

export const stepIcons: Record<StepState, IconName> = {
  running: "clock",
  done: "check",
  failed: "x",
  skipped: "minus",
};
