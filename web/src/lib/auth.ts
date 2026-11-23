import type { AuthState } from "../api/auth";
import type { ApiError } from "../api/client";
import type { ReauthConfirm } from "./confirmGesture";

// Ce que la barre latérale dit de l'accès : protégé par tel identifiant, ou
// par le mandataire pour telle identité. Rien tant que l'API n'a pas répondu,
// ni sans compte : l'écran de première configuration tient alors la place de
// l'interface.
interface AccessLabel {
  key: string;
  username: string;
}

export function accessLabel(state: AuthState | null): AccessLabel | null {
  if (state === null || state.mode === "none") {
    return null;
  }
  if (state.mode === "forward") {
    return { key: "auth.side_protected_forward", username: state.username };
  }
  return { key: "auth.side_protected", username: state.username };
}

// Sans compte, le serveur ne sert que la première configuration : l'écran
// la remplace. Jamais sur un doute, ni pendant le chargement.
export function needsFirstSetup(state: AuthState | null): boolean {
  return state !== null && state.mode === "none";
}

// En connexion native, sans session valable, le serveur ne sert que la
// connexion : l'écran la remplace. Jamais pendant le chargement.
export function needsSignIn(state: AuthState | null): boolean {
  return state !== null && state.mode === "native" && !state.signed_in;
}

// Ce que la connexion dit d'un refus : le serveur nomme ses refus, sauf le
// trop d'essais (429), qu'il rend en texte comme tout refus de débit. Le code
// demandé n'est pas un échec : le second écran le dit déjà.
export function loginFailure(error: ApiError | null): ApiError | string | null {
  if (error !== null && error.status === 429) {
    return "auth.login_too_many";
  }
  if (asksTOTP(error)) {
    return null;
  }
  return error;
}

// Le mode mandataire est actif mais sans preuve du passage par le mandataire :
// la page des réglages le dit, sans couper l'accès.
export function isForwardInsecure(state: AuthState | null): boolean {
  return state !== null && state.mode === "forward" && state.forward_insecure === true;
}

// Ce que la redemande d'un geste de niveau 4 demande : rien en SSO (R-A2-8),
// le mot de passe en native, et le code quand le serveur le dit actif.
export function reauthConfirmOf(state: AuthState): ReauthConfirm {
  return { mode: "reauth", sso: state.mode === "forward", code: state.totp === true };
}

// Le refus d'une connexion dont le mot de passe est juste mais qui attend le
// code à six chiffres : la page ouvre son second écran.
export function asksTOTP(error: ApiError | null): boolean {
  return error !== null && error.code === "auth.totp_required";
}

// Vérifie le formulaire avant l'envoi, pour dire l'erreur sans attendre ;
// le serveur reste le juge. Rend la clé du catalogue, ou null.
export function passwordFormError(password: string, confirmation: string, minLength: number): string | null {
  if ([...password].length < minLength) {
    return "auth.password_too_short";
  }
  if (password !== confirmation) {
    return "auth.password_mismatch";
  }
  return null;
}

// Le formulaire d'activation ou de changement : un identifiant (à
// l'activation seulement), le mot de passe actuel (au changement seulement),
// le mot de passe, sa confirmation.
interface CredentialsFormValues {
  username: string;
  current: string;
  password: string;
  confirmation: string;
}

export const emptyCredentialsForm: CredentialsFormValues = { username: "", current: "", password: "", confirmation: "" };

// L'en-tête que pose Authelia, proposé tel quel en mode mandataire.
export const defaultForwardHeader = "Remote-User";
