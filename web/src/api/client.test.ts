import { afterEach, expect, test, vi } from "vitest";

import { api, ApiError, errorKey, failureOf, onReauthRequired, onSessionLost, segment } from "./client";
import { route } from "./routes";

afterEach(() => {
  vi.unstubAllGlobals();
});

function recordFetch(): RequestInit[] {
  const calls: RequestInit[] = [];
  vi.stubGlobal("fetch", (_path: string, init: RequestInit) => {
    calls.push(init);
    return Promise.resolve(new Response(null, { status: 204 }));
  });
  return calls;
}

test("une écriture sans corps part en JSON avec {}", async () => {
  const calls = recordFetch();
  await api.send(route("POST /api/settings/api-tokens"));
  await api.send(route("DELETE /api/jobs/{id}", { id: "x" }));
  for (const init of calls) {
    expect(init.headers).toEqual({ "Content-Type": "application/json" });
    expect(init.body).toBe("{}");
  }
});

test("une écriture avec corps l'envoie tel quel, une lecture n'envoie rien", async () => {
  const calls = recordFetch();
  await api.send(route("PUT /api/session/language"), { language: "en" });
  await api.get("/api/session");
  expect(calls).toHaveLength(2);
  expect(calls[0]?.body).toBe('{"language":"en"}');
  expect(calls[1]?.headers).toBeUndefined();
  expect(calls[1]?.body).toBeUndefined();
});

test("un identifiant du serveur passe tel quel, encodé", () => {
  const ids = [
    "9f86d081884c7d65", // sonde, tâche, composant, incident
    "3f2b8c1e-5a4d-4e7b-9c1a-0d2e4f6a8b1c", // machine
    "local",
    "svc_9f86d081884c7d65",
    "unit_9f86d081884c7d65",
    "prj_9f86d081884c7d65",
    "apl_9f86d081884c7d65",
    "42", // alerte
    `local:${"a".repeat(64)}`, // conteneur : machine et identifiant Docker
  ];
  for (const id of ids) {
    expect(decodeURIComponent(segment(id))).toBe(id);
    expect(new URL(`/api/jobs/${segment(id)}`, "http://Kagu.test").pathname.split("/")).toHaveLength(4);
  }
});

test("un identifiant qui change le chemin lève la même erreur qu'un 404", () => {
  const forged = [
    "../x",
    "..",
    ".",
    "../../status/components/9f86d081884c7d65",
    "a/b",
    "a\\b",
    "a?b=c",
    "a#b",
    "%2e%2e",
    "%2F",
    "..%2F..%2Fstatus",
    "a b",
    "",
    "a".repeat(129),
  ];
  for (const id of forged) {
    expect(() => segment(id), JSON.stringify(id)).toThrow(ApiError);
    try {
      segment(id);
    } catch (error) {
      expect(error).toMatchObject({ status: 404, code: "not_found" });
    }
  }
});

test("un identifiant forgé ne sort jamais de sa collection", () => {
  // Ce que react-router rend d'un lien « /alertes/canaux/..%2F..%2Fstatus%2Fcomponents%2Fx ».
  const decoded = "../../status/components/x";
  const reached = (path: string) => new URL(path, "http://Kagu.test").pathname;
  expect(reached(`/api/alerts/channels/${decoded}`)).toBe("/api/status/components/x");
  expect(() => `/api/alerts/channels/${segment(decoded)}`).toThrow(ApiError);
});

test("un refus du serveur garde son code et son corps", () => {
  const refusal = new ApiError(409, "directory.service_linked", { links: { probes: [], components: [] } });
  expect(failureOf(refusal)).toBe(refusal);
  expect(errorKey(failureOf(refusal))).toBe("directory.service_linked");
});

test("ce qui n'est pas un refus du serveur se dit comme une erreur interne", () => {
  expect(errorKey(failureOf(new TypeError("Failed to fetch")))).toBe("error.internal");
  expect(failureOf("x").status).toBe(0);
});

function answer(status: number, error: string) {
  vi.stubGlobal("fetch", () => Promise.resolve(new Response(JSON.stringify({ error }), { status, headers: { "Content-Type": "application/json" } })));
}

test("une session morte (401 unauthorized) prévient qui l'écoute, une seule fois par réponse", async () => {
  let lost = 0;
  const stop = onSessionLost(() => {
    lost += 1;
  });
  answer(401, "unauthorized");
  await expect(api.get("/api/machines")).rejects.toMatchObject({ status: 401, code: "unauthorized" });
  expect(lost).toBe(1);
  stop();
  await expect(api.get("/api/machines")).rejects.toThrow(ApiError);
  expect(lost).toBe(1);
});

test("un mot de passe faux à la connexion n'est pas une session morte", async () => {
  let lost = 0;
  const stop = onSessionLost(() => {
    lost += 1;
  });
  answer(401, "auth.login_failed");
  await expect(api.send(route("POST /api/auth/login"), { username: "lucas", password: "faux" })).rejects.toMatchObject({ code: "auth.login_failed" });
  answer(403, "unauthorized");
  await expect(api.get("/api/machines")).rejects.toThrow(ApiError);
  stop();
  expect(lost).toBe(0);
});

// R-A2-7 côté écran : un 403 « auth.reauth_required » ouvre la fenêtre de
// redemande ; réussie, le geste se rejoue une fois ; abandonnée, le refus reste.
test("un geste refusé faute de redemande se rejoue après elle, une fois", async () => {
  const sent: string[] = [];
  let answers = [403, 204];
  vi.stubGlobal("fetch", (path: string) => {
    sent.push(path);
    const status = answers.shift() ?? 500;
    const body = status === 403 ? JSON.stringify({ error: "auth.reauth_required" }) : null;
    return Promise.resolve(new Response(body, { status }));
  });
  let asked = 0;
  const stop = onReauthRequired(() => {
    asked++;
    return Promise.resolve(true);
  });
  await api.send(route("DELETE /api/jobs/{id}", { id: "x" }));
  expect(asked).toBe(1);
  expect(sent).toEqual(["/api/jobs/x", "/api/jobs/x"]);

  answers = [403];
  stop();
  onReauthRequired(() => Promise.resolve(false));
  await expect(api.send(route("DELETE /api/jobs/{id}", { id: "x" }))).rejects.toMatchObject({ status: 403, code: "auth.reauth_required" });
  expect(sent).toHaveLength(3);
});
