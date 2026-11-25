import { mkdirSync } from "node:fs";

import type { Locator, Page } from "@playwright/test";

import { label } from "./support/catalog";
import { expect, test } from "./support/findings";

// L'onglet Droits de la fiche machine (T03-08, A3 R-A3-13) sur vps-droits des
// données fictives : un agent en « Gérer », terminal.host posé pour deux
// heures, le groupe Réseau pas permis. On y arrive par la barre d'onglets ;
// les noms de droits ne se lisent que sous « Voir le détail » et dans les
// lignes à coller ; l'onglet Agent n'en montre plus et y renvoie.
// Avec E2E_CAPTURES=1, il laisse la capture de l'onglet, un pli ouvert.

const captureFolder = new URL("../../docs/projet/refonte-ux/captures/", import.meta.url).pathname;
const capturing = process.env.E2E_CAPTURES === "1";
const machineName = "vps-droits";

// Les droits de la machine, par groupe, tels que le serveur les rend.
interface ServedGroup {
  name: string;
  rights: { name: string }[];
  grant_line: string;
  revoke_line: string;
}

async function servedGroups(page: Page): Promise<ServedGroup[]> {
  const answer = (await (await page.request.get("/api/machines")).json()) as { machines: { name: string; agent: { rights: { groups: ServedGroup[] } | null } | null }[] };
  const groups = answer.machines.find((machine) => machine.name === machineName)?.agent?.rights?.groups;
  expect(groups, "vps-droits des données fictives a rapporté ses droits").toBeDefined();
  return groups ?? [];
}

function groupCard(main: Locator, name: string): Locator {
  return main.locator("section.card", { has: main.page().locator(".card-t").getByText(label(`rights.group_${name}`), { exact: true }) });
}

// Le texte lisible de la colonne, sans les lignes à coller : un pli fermé ne
// se rend pas, innerText ne le lit donc pas.
async function visibleOutsideLines(main: Locator): Promise<string> {
  let text = await main.innerText();
  for (const line of await main.locator(".token-box code").allInnerTexts()) {
    text = text.split(line).join("");
  }
  return text;
}

test("onglet Droits : le jeu, cinq groupes, les noms repliés, les lignes du serveur", async ({ page, findings }) => {
  findings.where = "/machines/…/droits";
  await page.addInitScript(() => localStorage.setItem("theme", "light"));
  const groups = await servedGroups(page);
  expect(groups.map((group) => group.name)).toEqual(["see", "deploy", "backup", "enter", "network"]);

  // La fiche, puis l'onglet par sa barre.
  await page.goto("/machines");
  await page.locator("table a.svc", { hasText: machineName }).first().click();
  await page.locator("nav.tabs").getByRole("link", { name: label("tab.rights"), exact: true }).click();
  await expect(page).toHaveURL(/\/machines\/[^/]+\/droits$/);
  findings.screens.push("droits");
  findings.done.screens++;
  const main = page.locator(".machine-main");

  // Le jeu posé et sa phrase.
  const setCard = main.locator("section.card", { hasText: label("rights.set_title").replace("%s", machineName) });
  await expect(setCard.locator(".card-h")).toContainText(label("rights.manage"));
  await expect(setCard).toContainText(label("rights.manage_risk").split("{product}")[1]!.trim());

  // Cinq groupes, chacun sa phrase ; tous les plis fermés, aucun nom de droit
  // lisible hors des lignes à coller.
  for (const group of groups) {
    await expect(groupCard(main, group.name)).toContainText(label(`rights.group_${group.name}_hint`));
  }
  await expect(main.locator("details.fold[open]")).toHaveCount(0);
  const folded = await visibleOutsideLines(main);
  for (const right of groups.flatMap((group) => group.rights)) {
    expect(folded, `${right.name} lisible pli fermé`).not.toContain(right.name);
  }

  // Le groupe pas permis : sa ligne grant, ce qu'elle fera ; sous Entrer, le
  // terminal sur la machine.
  const network = groupCard(main, "network");
  await expect(network).toContainText(label("rights.not_allowed"));
  await expect(network.locator(".token-box code")).toHaveText(/^sudo \S+ agent grant network\.private$/);
  await expect(network).toContainText(label("rights.paste_shows_change"));
  const enter = groupCard(main, "enter");
  await expect(enter).toContainText(label("rights.host_terminal_risk"));
  // terminal.container est sans échéance : le groupe reste permis, sans heure.
  await expect(enter.locator(".card-h")).toHaveText(new RegExp(`${label("rights.allowed")}$`));

  // Chaque « Voir le détail » : les noms des droits, et la ligne revoke de
  // ce que le groupe porte.
  for (const group of groups) {
    const card = groupCard(main, group.name);
    await card.locator("details.fold > summary", { hasText: label("rights.see_detail") }).click();
    findings.done.buttons++;
    const detail = card.locator("details.fold[open] .fold-body");
    for (const right of group.rights) {
      await expect(detail.locator("code", { hasText: right.name }).first()).toBeVisible();
    }
    if (group.revoke_line !== "") {
      await expect(detail.locator(".token-box code")).toHaveText(group.revoke_line);
      await expect(detail).toContainText(label("rights.revoke_line"));
    }
    if (group.name === "enter") {
      // L'échéance de terminal.host se lit sur sa ligne.
      await expect(detail.locator("li", { hasText: "terminal.host" })).toContainText(label("rights.allowed_until").replace("%s", "").trim());
    }
    if (group.name === "deploy") {
      await expect(detail).toContainText(label("rights.worth_root_why"));
    }
    // Un seul pli ouvert à la fois pour la capture : on referme les autres.
    if (group.name !== "enter") {
      await card.locator("details.fold > summary").click();
    }
  }
  expect(groups.find((group) => group.name === "deploy")?.revoke_line).toMatch(/ agent revoke .*docker\.deploy/);

  if (capturing) {
    mkdirSync(captureFolder, { recursive: true });
    await page.clock.setFixedTime(new Date("2026-09-12T12:00:00Z"));
    await groupCard(main, "enter").scrollIntoViewIfNeeded();
    await page.screenshot({ path: `${captureFolder}A3-onglet-droits-clair.png`, fullPage: true });
  }

  // L'onglet Agent : plus de liste de droits, un renvoi à l'onglet Droits.
  await page.locator("nav.tabs").getByRole("link", { name: label("tab.agent"), exact: true }).click();
  await expect(page).toHaveURL(/\/machines\/[^/]+\/agent$/);
  const agentText = await visibleOutsideLines(main);
  for (const right of ["docker.deploy", "terminal.host", "restic.produce", "probe.lan"]) {
    expect(agentText, `${right} dans l'onglet Agent`).not.toContain(right);
  }
  await expect(main.locator("details.fold", { hasText: label("rights.see_detail") })).toHaveCount(0);
  await main.getByRole("link", { name: label("rights.open_tab") }).click();
  await expect(page).toHaveURL(/\/machines\/[^/]+\/droits$/);
  await expect(groupCard(main, "see")).toBeVisible();
  expect(findings.unknown()).toEqual([]);
});
