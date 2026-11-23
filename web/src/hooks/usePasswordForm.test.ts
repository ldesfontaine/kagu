import { expect, test } from "vitest";

import { submitPasswordForm } from "./usePasswordForm";

function submitWith(password: string, confirmation: string) {
  const sent: string[] = [];
  const refusal = submitPasswordForm({ username: "admin", password, confirmation }, 12, (values) => sent.push(values.password));
  return { refusal, sent };
}

test("un mot de passe trop court est refusé, rien n'est envoyé", () => {
  expect(submitWith("court", "court")).toEqual({ refusal: "auth.password_too_short", sent: [] });
});

test("une confirmation différente est refusée, rien n'est envoyé", () => {
  expect(submitWith("un-mot-de-passe-long", "un-autre-mot-de-passe")).toEqual({ refusal: "auth.password_mismatch", sent: [] });
});

test("un mot de passe juste appelle onValid une fois, sans refus", () => {
  expect(submitWith("un-mot-de-passe-long", "un-mot-de-passe-long")).toEqual({ refusal: null, sent: ["un-mot-de-passe-long"] });
});
