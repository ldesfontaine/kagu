import { expect, test } from "vitest";

import type { AuthState } from "../api/auth";
import { ApiError } from "../api/client";
import { accessLabel, isForwardInsecure, loginFailure, needsFirstSetup, needsSignIn, passwordFormError } from "./auth";

const unconfigured: AuthState = { mode: "none", username: "", enabled_at: null, password_min_length: 12, signed_in: false, allowed_users: null };
const native: AuthState = {
  mode: "native",
  username: "lucas",
  enabled_at: "2026-10-10T08:00:00Z",
  password_min_length: 12,
  signed_in: true,
  session: "9f86d081884c7d65",
  allowed_users: null,
};
const signedOut: AuthState = { mode: "native", username: "", enabled_at: null, password_min_length: 12, signed_in: false, allowed_users: null };
const forward: AuthState = {
  mode: "forward",
  username: "marie",
  header: "Remote-User",
  enabled_at: "2026-10-11T08:00:00Z",
  password_min_length: 12,
  signed_in: true,
  allowed_users: ["marie"],
};

test("accessLabel dit l'identifiant quand l'accès est protégé", () => {
  expect(accessLabel(native)).toEqual({ key: "auth.side_protected", username: "lucas" });
});

test("accessLabel dit le mandataire et l'identité qu'il transmet", () => {
  expect(accessLabel(forward)).toEqual({ key: "auth.side_protected_forward", username: "marie" });
});

test("accessLabel ne dit rien sans compte, ni avant la réponse", () => {
  expect(accessLabel(unconfigured)).toBeNull();
  expect(accessLabel(null)).toBeNull();
});

test("needsFirstSetup n'ouvre la première configuration que sur la réponse du serveur", () => {
  expect(needsFirstSetup(unconfigured)).toBe(true);
  expect(needsFirstSetup(native)).toBe(false);
  expect(needsFirstSetup(forward)).toBe(false);
  expect(needsFirstSetup(null)).toBe(false);
});

test("needsSignIn n'ouvre la connexion qu'en connexion native sans session", () => {
  expect(needsSignIn(signedOut)).toBe(true);
  expect(needsSignIn(native)).toBe(false);
  expect(needsSignIn(forward)).toBe(false);
  expect(needsSignIn(unconfigured)).toBe(false);
  expect(needsSignIn(null)).toBe(false);
});

test("loginFailure nomme le trop d'essais, laisse les autres refus au serveur", () => {
  expect(loginFailure(new ApiError(429, "internal"))).toBe("auth.login_too_many");
  const wrong = new ApiError(401, "auth.login_failed");
  expect(loginFailure(wrong)).toBe(wrong);
  expect(loginFailure(null)).toBeNull();
});

test("passwordFormError refuse un mot de passe trop court, compté en caractères", () => {
  expect(passwordFormError("onze carac.", "onze carac.", 12)).toBe("auth.password_too_short");
  expect(passwordFormError("éééééééééééé", "éééééééééééé", 12)).toBeNull();
});

test("passwordFormError refuse une confirmation différente", () => {
  expect(passwordFormError("correct horse battery", "correct horse batterie", 12)).toBe("auth.password_mismatch");
  expect(passwordFormError("correct horse battery", "correct horse battery", 12)).toBeNull();
});

test("isForwardInsecure ne parle que du mode mandataire que le serveur dit sans preuve", () => {
  expect(isForwardInsecure({ ...forward, forward_insecure: true })).toBe(true);
  expect(isForwardInsecure(forward)).toBe(false);
  expect(isForwardInsecure({ ...native, forward_insecure: true })).toBe(false);
  expect(isForwardInsecure(unconfigured)).toBe(false);
  expect(isForwardInsecure(null)).toBe(false);
});
