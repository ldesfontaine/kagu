import type { Page, Route } from "@playwright/test";

// La connexion native, simulée côté navigateur : l'état d'accès, les sessions
// et les gestes qui les changent. Le serveur des données fictives a déjà une
// session pour l'opérateur ; ces routes la remplacent par un état que le test
// pilote. Les écrans, eux, sont les vrais.

export interface FakeSession {
  id: string;
  user_agent: string;
  source: string;
  current: boolean;
}

export interface FakeAccess {
  signedIn: boolean;
  sessions: FakeSession[];
  // Les écritures reçues, « MÉTHODE chemin », dans l'ordre.
  writes: string[];
  // La prochaine lecture de la liste échoue.
  failSessionsRead: boolean;
}

export const someSessions: FakeSession[] = [
  {
    id: "aaaa000000000001",
    user_agent: "Mozilla/5.0 (X11; Linux x86_64) Firefox/133.0",
    source: "192.0.2.10",
    current: true,
  },
  {
    id: "aaaa000000000002",
    user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1) Safari/604.1",
    source: "2001:db8:1:2::/64",
    current: false,
  },
  {
    id: "aaaa000000000003",
    user_agent: "",
    source: "198.51.100.7",
    current: false,
  },
];

function authState(access: FakeAccess) {
  const base = { mode: "native", password_min_length: 12, allowed_users: null };
  if (!access.signedIn) {
    return { ...base, username: "", enabled_at: null, signed_in: false };
  }
  return {
    ...base,
    username: "lucas",
    enabled_at: "2026-09-01T08:00:00Z",
    signed_in: true,
    session: someSessions[0]?.id,
  };
}

function sessionsOf(access: FakeAccess) {
  const seen = new Date(Date.now() - 5 * 60_000).toISOString();
  return {
    sessions: access.sessions.map((session) => ({
      ...session,
      created_at: seen,
      seen_at: seen,
      expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    })),
  };
}

function record(access: FakeAccess, route: Route): void {
  const request = route.request();
  access.writes.push(`${request.method()} ${new URL(request.url()).pathname}`);
}

// mockNativeAccess pose les routes de l'accès et rend l'état que le test
// modifie au fil des gestes.
export async function mockNativeAccess(
  page: Page,
  signedIn: boolean,
): Promise<FakeAccess> {
  const access: FakeAccess = {
    signedIn,
    sessions: someSessions.map((session) => ({ ...session })),
    writes: [],
    failSessionsRead: false,
  };
  await page.route("**/api/auth", (route) =>
    route.fulfill({ json: authState(access) }),
  );
  await page.route("**/api/auth/sessions", (route) => {
    if (access.failSessionsRead) {
      return route.fulfill({ status: 500, json: { error: "internal" } });
    }
    return route.fulfill({ json: sessionsOf(access) });
  });
  await page.route("**/api/auth/sessions/*", (route) => {
    record(access, route);
    const id = new URL(route.request().url()).pathname.split("/").pop();
    access.sessions = access.sessions.filter((session) => session.id !== id);
    return route.fulfill({ status: 204 });
  });
  await page.route("**/api/auth/sessions/actions/close-others", (route) => {
    record(access, route);
    const closed = access.sessions.filter((session) => !session.current).length;
    access.sessions = access.sessions.filter((session) => session.current);
    return route.fulfill({ json: { closed } });
  });
  await page.route("**/api/auth/logout", (route) => {
    record(access, route);
    access.signedIn = false;
    return route.fulfill({ status: 204 });
  });
  return access;
}

// La connexion : un nom et un mot de passe saisis, puis « Se connecter ».
export async function signInWith(
  page: Page,
  username: string,
  password: string,
): Promise<void> {
  await page.locator("#auth-username").fill(username);
  await page.locator("#auth-password").fill(password);
  await page.locator("form button[type=submit]").click();
}
