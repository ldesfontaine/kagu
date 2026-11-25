import { label } from "./support/catalog";
import { expect, test } from "./support/findings";

// Essai E03-08 sur vps-refusee des données fictives : sa politique n'est pas
// à root, l'agent le dit. L'onglet Droits lit « Refusée », jamais
// « Personnalisé », dit la raison avec le chemin en cause, et donne la
// commande que le serveur écrit.

const machineName = "vps-refusee";

interface ServedRefusal {
  reason: string;
  detail: string;
  fix_line: string;
}

test("onglet Droits : une politique refusée dit pourquoi et comment corriger", async ({ page, findings }) => {
  findings.where = "/machines/…/droits";
  const answer = (await (await page.request.get("/api/machines")).json()) as { machines: { name: string; agent: { policy_refusal: ServedRefusal | null } | null }[] };
  const refusal = answer.machines.find((machine) => machine.name === machineName)?.agent?.policy_refusal;
  expect(refusal, "vps-refusee des données fictives a dit la raison du refus").toBeTruthy();
  const served = refusal!;
  expect(served.reason).toBe("owner");
  expect(served.fix_line).toBe(`sudo chown root ${served.detail}`);

  await page.goto("/machines");
  await page.locator("table a.svc", { hasText: machineName }).first().click();
  await page.locator("nav.tabs").getByRole("link", { name: label("tab.rights"), exact: true }).click();
  await expect(page).toHaveURL(/\/machines\/[^/]+\/droits$/);
  findings.screens.push("droits-refusee");
  findings.done.screens++;
  const main = page.locator(".machine-main");

  const setCard = main.locator("section.card", { hasText: label("rights.set_title").replace("%s", machineName) });
  await expect(setCard.locator(".card-h")).toContainText(label("rights.refused"));
  await expect(setCard.locator(".card-h")).not.toContainText(label("rights.custom"));
  await expect(setCard).toContainText(label("rights.refusal_owner").replace("%s", served.detail));
  await expect(setCard.locator(".token-box code").first()).toHaveText(served.fix_line);
  // La phrase générale d'un agent qui ne dit pas la raison ne s'ajoute pas.
  await expect(main).not.toContainText(label("machine.agent_policy_refused").split("%s")[0]!.trim());
  expect(findings.unknown()).toEqual([]);
});
