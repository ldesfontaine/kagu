import type { ActionState } from "../api/actions";
import type { Tone } from "./tone";

// Le ton de la pastille d'un ordre selon son état.
export const stateTones: Record<ActionState, Tone> = {
  queued: "neutral",
  sent: "neutral",
  accepted: "accent",
  refused: "danger",
  succeeded: "ok",
  failed: "danger",
  expired: "warn",
};
