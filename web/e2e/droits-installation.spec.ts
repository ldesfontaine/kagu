import type { Page } from "@playwright/test";

import { label } from "./support/catalog";
import { expect, test } from "./support/findings";

// L'ajout d'une machine (B1) : un jeu de droits, deux lignes à coller ; puis
// (U1, #447) un refus de droit qui porte son geste, et un sélecteur de
// machine qui grise celles qui ne conviennent pas. Chaque geste est joué
// comme un opérateur le ferait, sur les données fictives.

// Le banc écoute en clair : sans adresse publique en https, l'ajout y est
// fermé (R-B1-13). La liste des machines est relue telle que le serveur la
// rend, l'ajout seul y est ouvert ou fermé ; le jeton est inventé.
const joinCommand = "curl -fsSL https://exemple.org/install.sh | sudo sh -s -- join --server https://kagu.exemple.fr --server-key SHA256:exemple --rights manage";
const joinToken = "kg_exemple_de_jeton_inventé_0000";
const joinTokenID = "jeton-essai-1";

async function withJoin(page: Page, ready: boolean): Promise<{ bodies: unknown[] }> {
  const sent = { bodies: [] as unknown[] };
  await page.route("**/api/machines", async (route) => {
    if (route.request().method() !== "GET") {
      await route.fallback();
      return;
    }
    const response = await route.fetch();
    const body = (await response.json()) as { join: { ready: boolean; domain_line: string } };
    body.join = { ...body.join, ready, domain_line: "sudo kagu setup --domain" };
    await route.fulfill({ response, json: body });
  });
  await page.route("**/api/machines/tokens", async (route) => {
    sent.bodies.push(route.request().postDataJSON());
    await route.fulfill({
      status: 201,
      json: { id: joinTokenID, name: "vps-essai-1", token: joinToken, set: "manage", command: joinCommand, reenroll_lines: [], expires_at: new Date(Date.now() + 3_480_000).toISOString() },
    });
  });
  // L'avancement que join aurait écrit sur le jeton (R-B1-11).
  await page.route(`**/api/machines/tokens/${joinTokenID}/progress`, async (route) => {
    await route.fulfill({
      json: { state: "pending", expires_at: new Date(Date.now() + 3_480_000).toISOString(), steps: [{ key: "step.enroll.system", state: "done", detail: "Debian 12, amd64", at: new Date().toISOString() }] },
    });
  });
  return sent;
}

test("Ajouter une machine : trois jeux, aucun nom de droit replié, deux lignes et un seul Copier", async ({ page, findings }) => {
  findings.where = "/machines/nouvelle";
  const sent = await withJoin(page, true);
  await page.goto("/machines/nouvelle");
  const dialog = page.locator("dialog[open]");
  await dialog.getByLabel(label("machine.name_label")).fill("vps-essai-1");

  // Trois cartes, aucune case à cocher ; plis fermés, aucun nom de droit ne se lit.
  await expect(dialog.getByRole("radio")).toHaveCount(3);
  await expect(dialog.getByRole("checkbox")).toHaveCount(0);
  await expect(dialog.getByText("docker.deploy", { exact: true }).first()).toBeHidden();
  await dialog.locator("input[type=radio][value=manage]").check();
  await dialog.locator(".pick-more summary").nth(1).click();
  await expect(dialog.getByText("docker.deploy", { exact: true }).first()).toBeVisible();
  await dialog.getByRole("button", { name: label("machine.create_token") }).click();
  expect(sent.bodies).toEqual([{ name: "vps-essai-1", role: "generic", set: "manage" }]);

  // La commande sans le jeton ; le jeton à part ; un seul « Copier ».
  await expect(dialog.locator(".token-box")).toHaveCount(1);
  await expect(dialog.locator(".token-box")).toContainText(joinCommand);
  await expect(dialog.locator(".token-box")).not.toContainText(joinToken);
  await expect(dialog).toContainText(joinToken);
  await expect(dialog.getByRole("button", { name: label("machine.copy") })).toHaveCount(1);
  await dialog.getByRole("button", { name: label("machine.copy") }).click();
  await expect(dialog.getByRole("button", { name: new RegExp(`${label("machine.copied")}|${label("machine.copy_failed")}`) })).toBeVisible();

  await dialog.getByRole("button", { name: label("wizard.next") }).click();
  await expect(dialog.locator(".wizard-step-current")).toContainText(label("machine.step_wait"));
  await expect(dialog.locator(".step-trail")).toContainText(label("step.enroll.system"));
  await expect(dialog.locator(".step-trail")).toContainText("Debian 12, amd64");
  await dialog.locator(".modal-foot").getByRole("button", { name: label("modal.close") }).click();
  await expect(dialog).toHaveCount(0);
  expect(findings.unknown()).toEqual([]);
});

test("Sans domaine en https, « Ajouter une machine » est grisé et la commande setup --domain est donnée", async ({ page, findings }) => {
  findings.where = "/machines (sans domaine)";
  await withJoin(page, false);
  await page.goto("/machines");
  await expect(page.getByRole("button", { name: label("machine.add") })).toBeDisabled();
  await expect(page.locator("main")).toContainText(label("machine.join_needs_domain_note").replaceAll("{product}", "Kagu"));
  await expect(page.locator(".token-box", { hasText: "sudo kagu setup --domain" })).toBeVisible();
  expect(findings.unknown()).toEqual([]);
  // Le direct relit la liste : une relecture en vol ne doit pas survivre à la page.
  await page.unrouteAll({ behavior: "ignoreErrors" });
});

test("Hôte Proxmox sans sudo : la migration de l'agent se colle en root, binaire téléchargé et vérifié", async ({ page, findings }) => {
  findings.where = "/machines (agent d'un hôte Proxmox)";
  // La fiche d'un hôte Proxmox dont l'agent n'est pas migré : le bloc est en root d'office.
  await page.route("**/api/machines/*/agent-update", (route) =>
    route.fulfill({ json: { current: "v0.0.1", target: "v0.0.2", arch: "amd64", available: false, reason: "rollback_unavailable" } }),
  );
  await page.route("**/api/machines", async (route) => {
    const response = await route.fetch();
    const body = (await response.json()) as { machines: { role: string }[] };
    body.machines.forEach((machine) => (machine.role = "proxmox"));
    await route.fulfill({ response, json: body });
  });
  await page.goto("/machines");
  await page.locator("table a.svc").first().click();
  await page.goto(`${new URL(page.url()).pathname.replace(/\/$/, "")}/agent`);
  const migration = page.locator(".note", { hasText: label("machine.agent_migration_title") });
  await expect(migration.getByRole("button", { name: label("machine.agent_migration_root") })).toHaveAttribute("aria-pressed", "true");
  let block = await migration.locator(".token-box pre").innerText();
  expect(block).not.toMatch(/\bsudo\b/);
  expect(block).toContain("sha256sum -c --ignore-missing SHA256SUMS");
  expect(block).toContain("runuser -u kagu-agent -- install");
  // L'autre variante reste au choix.
  await migration.getByRole("button", { name: label("machine.agent_migration_sudo") }).click();
  block = await migration.locator(".token-box pre").innerText();
  expect(block).toContain("sudo systemctl stop kagu-agent.service");
  expect(findings.unknown()).toEqual([]);
});

test("Destination de sauvegarde : les machines sans le droit sont grisées, avec la raison et le lien", async ({ page, findings }) => {
  findings.where = "/sauvegardes/destinations/nouvelle";
  await page.goto("/sauvegardes/destinations/nouvelle");
  const dialog = page.locator("dialog[open]");
  await dialog.locator("#backup-destination-machine").click();
  const list = page.locator("[role=listbox]").last();
  const grayed = list.locator("[role=option][aria-disabled=true]");
  const usable = list.locator("[role=option]:not([aria-disabled=true])");
  expect(await grayed.count()).toBeGreaterThan(0);
  expect(await usable.count()).toBeGreaterThan(0);
  const first = grayed.first();
  const note = list.locator(".select-option-group").first();
  await expect(note.locator(".select-option-reason")).toContainText(label("machine.fit_right_missing").replace("%s", "").trim().slice(0, 10));
  // Cliquer la ligne grisée ne la choisit pas.
  await first.click({ position: { x: 8, y: 8 }, force: true });
  await expect(list).toBeVisible();
  // Le lien mène à l'onglet Agent de la machine, qui montre la ligne grant.
  await note.getByRole("link", { name: label("machine.grant_right") }).click();
  await expect(page).toHaveURL(/\/machines\/[^/]+\/agent\?droit=backup\.receive/);
  await expect(page.locator(".note .token-box", { hasText: "agent grant --pending" })).toBeVisible();
  expect(findings.unknown()).toEqual([]);
});

test("Sonde : une machine sans agent est grisée dans le sélecteur", async ({ page, findings }) => {
  findings.where = "/disponibilite/nouvelle";
  await page.goto("/disponibilite/nouvelle");
  const dialog = page.locator("dialog[open]");
  await dialog.locator("details.fold > summary").first().click();
  await dialog.locator("#probe-machine").click();
  const list = page.locator("[role=listbox]").last();
  await expect(list.locator("[role=option]").first()).toBeVisible();
  // Les options grisées, s'il y en a, portent toutes leur raison et leur lien.
  const grayed = list.locator("[role=option][aria-disabled=true]");
  for (let index = 0; index < (await grayed.count()); index++) {
    await expect(list.locator(".select-option-group .select-option-reason a").nth(index)).toBeVisible();
  }
  await page.keyboard.press("Escape");
  expect(findings.unknown()).toEqual([]);
});
