import { expect, test, type Page } from "@playwright/test";

import { label } from "./support/catalog";
import { mockNativeAccess } from "./support/access";

// Les captures de A2 (docs/projet/refonte-ux/captures/A2-*.png) : la page de
// connexion, et Réglages › Accès avec ses sessions. État d'accès simulé,
// données fictives. Hors `make ci` : `E2E_CAPTURES=1 npm run e2e`.
test.skip(
  process.env.E2E_CAPTURES !== "1",
  "captures demandées par E2E_CAPTURES=1",
);

const folder = new URL(
  "../../docs/projet/refonte-ux/captures/",
  import.meta.url,
);

async function shoot(
  page: Page,
  name: string,
  theme: "light" | "dark",
): Promise<void> {
  await page.screenshot({
    path: new URL(
      `A2-${name}-${theme === "light" ? "clair" : "sombre"}.png`,
      folder,
    ).pathname,
  });
}

for (const theme of ["light", "dark"] as const) {
  test.describe(theme, () => {
    test.beforeEach(async ({ page }) => {
      await page.addInitScript(
        (value) => localStorage.setItem("theme", value),
        theme,
      );
    });

    test(`connexion ${theme}`, async ({ page }) => {
      await mockNativeAccess(page, false);
      await page.goto("/");
      await expect(
        page
          .locator(".card-t")
          .getByText(label("auth.login_title"), { exact: true }),
      ).toBeVisible();
      await shoot(page, "connexion", theme);
    });

    test(`sessions ${theme}`, async ({ page }) => {
      await mockNativeAccess(page, true);
      await page.goto("/parametres#acces");
      const section = page.locator("#acces");
      await expect(section.locator("tbody tr")).toHaveCount(3);
      await section
        .getByText(label("auth.sessions_title"), { exact: true })
        .scrollIntoViewIfNeeded();
      await shoot(page, "sessions", theme);
    });
  });
}
