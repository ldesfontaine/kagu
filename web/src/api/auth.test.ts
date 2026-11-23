import { afterEach, expect, test, vi } from "vitest";

import { changePassword } from "./auth";

afterEach(() => {
  vi.unstubAllGlobals();
});

test("changer le mot de passe envoie l'actuel avec le nouveau, et rend le nombre de jetons d'API", async () => {
  const sent: { path: string; init: RequestInit }[] = [];
  vi.stubGlobal("fetch", (path: string, init: RequestInit) => {
    sent.push({ path, init });
    return Promise.resolve(new Response(JSON.stringify({ mode: "basic", api_tokens: 2 }), { status: 200, headers: { "Content-Type": "application/json" } }));
  });
  const change = await changePassword("le-mot-de-passe-actuel", "un-mot-de-passe-long");
  expect(sent).toHaveLength(1);
  expect(sent[0]?.path).toBe("/api/auth/password");
  expect(sent[0]?.init.method).toBe("PUT");
  expect(JSON.parse(String(sent[0]?.init.body))).toEqual({ current: "le-mot-de-passe-actuel", password: "un-mot-de-passe-long" });
  expect(change.api_tokens).toBe(2);
});
