import { expect, test, type Page } from "@playwright/test";

import { label } from "./support/catalog";
import { mockNativeAccess, signInWith } from "./support/access";

// A2, la connexion native (T02-06) : la page de connexion et ses refus, le
// retour à la connexion quand la session meurt, les sessions sous Réglages ›
// Accès, la première configuration qui ouvre l'interface sans repasser par la
// connexion. L'état d'accès est simulé (support/access.ts) ; les écrans sont
// les vrais.

const loginPage = (page: Page) =>
  page.locator(".card-t").getByText(label("auth.login_title"), { exact: true });
const sideMenu = (page: Page) => page.locator("#side");

test("connexion : refus sans dire lequel, trop d'essais, puis la bonne ouvre l'interface", async ({
  page,
}) => {
  const access = await mockNativeAccess(page, false);
  const answers = [
    { status: 401, json: { error: "auth.login_failed" } },
    { status: 429, body: "too many requests" },
  ];
  const logins: unknown[] = [];
  await page.route("**/api/auth/login", (route) => {
    logins.push(route.request().postDataJSON());
    const answer = answers.shift();
    if (answer !== undefined) {
      return route.fulfill(answer);
    }
    access.signedIn = true;
    return route.fulfill({
      json: {
        mode: "native",
        username: "lucas",
        signed_in: true,
        session: "aaaa000000000001",
      },
    });
  });

  await page.goto("/");
  await expect(loginPage(page)).toBeVisible();
  await expect(sideMenu(page)).toHaveCount(0);

  await signInWith(page, "lucas", "pas le bon mot de passe");
  await expect(
    page.getByText(label("auth.login_failed"), { exact: true }),
  ).toBeVisible();
  // Le refus ne dit pas lequel des deux est faux : aucune phrase ne vise l'un
  // seul.
  await expect(
    page.getByText(/^(nom|identifiant|mot de passe) (faux|incorrect|inconnu)/i),
  ).toHaveCount(0);

  await signInWith(page, "lucas", "pas le bon mot de passe");
  await expect(
    page.getByText(label("auth.login_too_many"), { exact: true }),
  ).toBeVisible();

  await signInWith(page, "lucas", "correct horse battery");
  await expect(sideMenu(page)).toBeVisible();
  await expect(loginPage(page)).toHaveCount(0);
  expect(logins).toEqual([
    { username: "lucas", password: "pas le bon mot de passe", code: "" },
    { username: "lucas", password: "pas le bon mot de passe", code: "" },
    { username: "lucas", password: "correct horse battery", code: "" },
  ]);
});

test("une session perdue en cours d'usage ramène à la connexion", async ({
  page,
}) => {
  const access = await mockNativeAccess(page, true);
  let sessionLost = false;
  await page.route("**/api/machines", (route) => {
    if (!sessionLost) {
      return route.fallback();
    }
    return route.fulfill({ status: 401, json: { error: "unauthorized" } });
  });

  await page.goto("/");
  await expect(sideMenu(page)).toBeVisible();
  // La session meurt côté serveur ; le prochain geste dans l'interface le voit.
  sessionLost = true;
  access.signedIn = false;
  // Une lecture en cours peut recevoir le 401 avant le clic : la porte démonte
  // alors le menu, et le lien n'existe plus. Les deux ordres mènent à la
  // connexion ; on attend cet état, pas le premier lien trouvé.
  await Promise.race([
    sideMenu(page).locator('a[href="/machines"]').first().click(),
    loginPage(page).waitFor(),
  ]);
  await expect(loginPage(page)).toBeVisible();
});

async function openAccessSection(page: Page) {
  await page.goto("/parametres#acces");
  const section = page.locator("#acces");
  await expect(
    section.getByText(label("auth.sessions_title"), { exact: true }),
  ).toBeVisible();
  return section;
}

test("Réglages › Accès : fermer une session, fermer les autres, se déconnecter", async ({
  page,
}) => {
  const access = await mockNativeAccess(page, true);
  const section = await openAccessSection(page);
  const rows = section.locator("tbody tr");

  await expect(rows).toHaveCount(3);
  await expect(
    rows.filter({ hasText: label("auth.session_current") }),
  ).toHaveCount(1);
  await expect(rows.filter({ hasText: "Firefox/133.0" })).toContainText(
    label("auth.session_current"),
  );
  await expect(
    rows.filter({ hasText: label("auth.session_no_browser") }),
  ).toHaveCount(1);

  // Fermer une autre session : la route est appelée, la liste relue.
  await rows
    .filter({ hasText: "iPhone" })
    .getByRole("button", { name: label("auth.session_close"), exact: true })
    .click();
  await expect(rows).toHaveCount(2);
  expect(access.writes).toContain("DELETE /api/auth/sessions/aaaa000000000002");

  const closeOthers = section.getByRole("button", {
    name: label("auth.sessions_close_others"),
    exact: true,
  });
  await expect(closeOthers).toBeEnabled();
  await closeOthers.click();
  await expect(rows).toHaveCount(1);
  expect(access.writes).toContain(
    "POST /api/auth/sessions/actions/close-others",
  );
  // Plus d'autre session : le bouton ne propose plus rien.
  await expect(closeOthers).toBeDisabled();

  await section
    .getByRole("button", { name: label("auth.logout"), exact: true })
    .click();
  await expect(loginPage(page)).toBeVisible();
  expect(access.writes).toContain("POST /api/auth/logout");
});

test("Réglages › Accès : une liste illisible montre l'erreur, pas une liste vide", async ({
  page,
}) => {
  const access = await mockNativeAccess(page, true);
  access.failSessionsRead = true;
  await page.goto("/parametres#acces");
  const section = page.locator("#acces");
  await expect(
    section.getByText(label("auth.sessions_title"), { exact: true }),
  ).toBeVisible();
  await expect(
    section.getByText(label("error.internal"), { exact: true }),
  ).toBeVisible();
  await expect(section.locator("tbody tr")).toHaveCount(0);
});

test("première configuration native : le compte créé, l'interface s'ouvre sans repasser par la connexion", async ({
  page,
}) => {
  let configured = false;
  const setups: unknown[] = [];
  await page.route("**/api/auth", (route) =>
    route.fulfill({
      json: configured
        ? {
            mode: "native",
            username: "admin",
            enabled_at: "2026-09-01T08:00:00Z",
            password_min_length: 12,
            signed_in: true,
            session: "bbbb000000000001",
            allowed_users: null,
          }
        : {
            mode: "none",
            username: "",
            enabled_at: null,
            password_min_length: 12,
            signed_in: false,
            allowed_users: null,
          },
    }),
  );
  await page.route("**/api/auth/setup", (route) => {
    setups.push(route.request().postDataJSON());
    configured = true;
    return route.fulfill({
      json: {
        mode: "native",
        username: "admin",
        enabled_at: "2026-09-01T08:00:00Z",
        password_min_length: 12,
        signed_in: true,
        session: "bbbb000000000001",
        allowed_users: null,
        api_tokens_revoked: 0,
      },
    });
  });
  await page.route("**/api/auth/totp/proposal", (route) =>
    route.fulfill({ json: { secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", uri: "otpauth://totp/x", qr_code: "data:image/png;base64," } }),
  );

  await page.goto("/");
  await expect(
    page.getByText(label("auth.setup_title"), { exact: true }),
  ).toBeVisible();
  await page.locator("#auth-setup-code").fill("12345678");
  await page.locator("#auth-username").fill("admin");
  await page.locator("#auth-password").fill("une-phrase-de-passe-de-test");
  await page.locator("#auth-confirm").fill("une-phrase-de-passe-de-test");
  await page.locator("form button[type=submit]").click();
  // La marche 3 propose le code à six chiffres ; il n'est jamais imposé.
  await page.getByRole("button", { name: label("auth.totp_later") }).click();

  await expect(sideMenu(page)).toBeVisible();
  await expect(loginPage(page)).toHaveCount(0);
  expect(setups).toEqual([
    {
      mode: "native",
      setup_code: "12345678",
      username: "admin",
      password: "une-phrase-de-passe-de-test",
    },
  ]);
});
