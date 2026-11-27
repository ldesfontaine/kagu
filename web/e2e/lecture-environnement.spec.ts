import type { Page } from "@playwright/test";

import { label } from "./support/catalog";
import { expect, test } from "./support/findings";

// Le chantier L5 : l'environnement des conteneurs, lu sous un droit à part.
// Le droit « observe.env » est refusé par défaut, posé en root sur la
// machine ; sans lui, la fiche d'un service le dit et porte
// le geste qui y mène. Les données fictives portent, sur la machine distante
// (dont l'agent n'a pas le droit), « notes » et sa base « notes-db », et le
// lien que l'environnement de « notes » désigne.

const linkRows = (page: Page) => page.locator("main section", { has: page.getByText(label("link.title"), { exact: true }) }).locator("tbody tr");

async function openService(page: Page, name: string): Promise<void> {
  await page.goto("/services");
  await page.locator("main").getByRole("link", { name: new RegExp(`^${name}(\\s|$)`) }).first().click();
  await expect(page.getByRole("heading", { name, exact: true })).toBeVisible();
}

test("Fiche d'un service : le lien lu dans l'environnement se lit avec sa source, son port et sa fraîcheur", async ({ page, findings }) => {
  findings.where = "/services/annuaire/notes (liens)";
  await openService(page, "notes");
  await expect(linkRows(page)).toHaveCount(1);
  const row = linkRows(page).first();
  await expect(row).toContainText(label("link.outgoing"));
  await expect(row).toContainText(label("link.nature_config"));
  await expect(row).toContainText(label("link.proof_deduced"));
  await expect(row).toContainText(label("link.signal_environment"));
  await expect(row).toContainText("5432");
  await expect(row.getByRole("link", { name: "notes-db", exact: true })).toBeVisible();
  // Écrit à chaque inventaire de l'agent : il se dit « vu », jamais « calculé à l'instant ».
  await expect(row).not.toContainText(label("link.deduced_fresh"));
  await expect(row).toContainText(label("link.seen").replace("%s", "").trim());
  // Ce n'est pas une route à décider : ni Confirmer, ni Écarter, ni Retirer ; seulement où le changer.
  for (const name of ["link.confirm", "link.dismiss", "link.remove"]) {
    await expect(row.getByRole("button", { name: label(name), exact: true })).toHaveCount(0);
  }
  await expect(row.locator("[title]", { hasText: "—" })).toHaveAttribute("title", label("link.from_environment_help"));
  // L'autre bout voit le même lien du côté qui l'utilise.
  await row.getByRole("link", { name: "notes-db", exact: true }).click();
  await expect(page.getByRole("heading", { name: "notes-db", exact: true })).toBeVisible();
  await expect(linkRows(page).first()).toContainText(label("link.incoming"));
  expect(findings.unknown()).toEqual([]);
});

test("Droit manquant : la carte Liens le dit et porte la ligne grant du serveur", async ({ page, findings }) => {
  findings.where = "/services/annuaire/notes (droit manquant)";
  await openService(page, "notes");
  const note = page.locator(".note", { hasText: label("link.environment_off") });
  await expect(note).toBeVisible();
  await expect(note.locator(".token-box", { hasText: "agent grant --pending" })).toBeVisible();
  await expect(note.getByRole("link", { name: /reenroller/ })).toHaveCount(0);
  expect(findings.unknown()).toEqual([]);
});

test("Un service sur binaire n'a pas la note : l'environnement d'une unité systemd ne se lit pas", async ({ page, findings }) => {
  findings.where = "/services/annuaire/caddy (pas de note)";
  await openService(page, "caddy");
  await expect(linkRows(page).first()).toBeVisible();
  await expect(page.locator(".note", { hasText: label("link.environment_off") })).toHaveCount(0);
  expect(findings.unknown()).toEqual([]);
});
