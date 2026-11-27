import type { Page } from "@playwright/test";

import { label } from "./support/catalog";
import { expect, test } from "@playwright/test";

// Les captures de U1 (docs/projet/refonte-ux/captures/U1-*.png) : un sélecteur
// qui grise les machines qui ne conviennent pas et la fiche d'un agent qui n'a
// pas le droit de se mettre à jour. Données fictives seulement (l'offre de
// mise à jour est simulée côté navigateur). Hors `make ci` : `E2E_CAPTURES=1 npm run e2e`.
test.skip(process.env.E2E_CAPTURES !== "1", "captures demandées par E2E_CAPTURES=1");

const folder = new URL("../../docs/projet/refonte-ux/captures/", import.meta.url);

async function shoot(page: Page, name: string, theme: "light" | "dark"): Promise<void> {
  await page.screenshot({ path: new URL(`U1-${name}-${theme === "light" ? "clair" : "sombre"}.png`, folder).pathname });
}

for (const theme of ["light", "dark"] as const) {
  test.describe(theme, () => {
    test.beforeEach(async ({ page }) => {
      await page.addInitScript((value) => localStorage.setItem("theme", value), theme);
      await page.setViewportSize({ width: 1280, height: 1100 });
    });

    test(`ligne grant d'un droit ${theme}`, async ({ page }) => {
      await page.goto("/sauvegardes/destinations/nouvelle");
      await page.locator("dialog[open] #backup-destination-machine").click();
      await shoot(page, "destination-menu-machines", theme);
      const note = page.locator("[role=listbox] .select-option-group").first();
      await note.getByRole("link", { name: label("machine.grant_right") }).click();
      await expect(page.locator(".note .token-box", { hasText: "agent grant --pending" })).toBeVisible();
      await shoot(page, "agent-ligne-grant", theme);
    });

    test(`plan de sauvegarde ${theme}`, async ({ page }) => {
      await page.goto("/sauvegardes/plans/nouveau");
      const dialog = page.locator("dialog[open]");
      await dialog.locator("#backup-plan-kind").click();
      await page.locator("[role=listbox] [role=option]").filter({ hasText: label("backup.source_kind_agent") }).click();
      await dialog.locator("#backup-plan-machine").click();
      await expect(page.locator("[role=listbox]")).toBeVisible();
      await shoot(page, "plan-menu-machines", theme);
    });

    test(`agent sans le droit ${theme}`, async ({ page }) => {
      await page.route("**/api/machines/*/agent-update", (route) =>
        route.fulfill({ json: { current: "v0.0.1", target: "v0.0.2", arch: "amd64", available: false, reason: "right_missing" } }),
      );
      await page.goto("/machines");
      await page.locator("table a.svc").first().click();
      await page.goto(`${new URL(page.url()).pathname.replace(/\/$/, "")}/agent`);
      await expect(page.locator(".token-box", { hasText: "agent grant --pending" })).toBeVisible();
      await shoot(page, "agent-droit-manquant", theme);
    });
  });
}
