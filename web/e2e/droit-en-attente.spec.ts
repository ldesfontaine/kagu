import { label } from "./support/catalog";
import { expect, test } from "./support/findings";

// R-DROIT-8, R-A3-15 (E03-07) : un geste fermé faute de droit donne la ligne
// constante « grant --pending », jamais une ligne qui nomme le droit ; le droit
// se dit à côté, avec l'avertissement de ne coller en root aucune autre ligne.
// Vu en clair et en sombre, sur l'onglet Agent d'une machine sans
// backup.receive (le lien d'une destination grisée y mène) et sur le groupe
// pas permis de l'onglet Droits de vps-droits.

const productPart = (key: string): string => label(key).split("{product}")[0]!.trim();

for (const theme of ["light", "dark"] as const) {
  test(`geste fermé, ${theme} : la ligne constante et l'avertissement`, async ({ page, findings }) => {
    findings.where = `/machines/…/agent?droit=… (${theme})`;
    await page.addInitScript((value) => localStorage.setItem("theme", value), theme);

    await page.goto("/sauvegardes/destinations/nouvelle");
    await page.locator("dialog[open] #backup-destination-machine").click();
    const note = page.locator("[role=listbox] .select-option-group").first();
    await note.getByRole("link", { name: label("machine.grant_right") }).click();
    await expect(page).toHaveURL(/\/machines\/[^/]+\/agent\?droit=backup\.receive/);
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    findings.screens.push(`agent-${theme}`);
    findings.done.screens++;

    const locked = page.locator(".note", { has: page.locator(".token-box") }).filter({ hasText: label("rights.paste_shows_change") });
    await expect(locked.locator(".token-box code")).toHaveText(/^sudo \S+ agent grant --pending$/);
    await expect(locked).toContainText(label("rights.missing_right").replace("%s", "backup.receive"));
    await expect(locked).toContainText(productPart("rights.paste_only_pending"));
    for (const code of await page.locator(".token-box code").allInnerTexts()) {
      expect(code, "une ligne à coller qui nomme un droit").not.toMatch(/ agent grant [a-z]/);
    }

    // L'onglet Droits : le groupe pas permis porte la même ligne et la même
    // phrase.
    await page.goto("/machines");
    await page.locator("table a.svc", { hasText: "vps-droits" }).first().click();
    await page.locator("nav.tabs").getByRole("link", { name: label("tab.rights"), exact: true }).click();
    const network = page.locator(".machine-main section.card", { has: page.locator(".card-t").getByText(label("rights.group_network"), { exact: true }) });
    await expect(network.locator(".token-box code")).toHaveText(/^sudo \S+ agent grant --pending$/);
    await expect(network).toContainText(productPart("rights.paste_only_pending"));
    findings.screens.push(`droits-${theme}`);
    findings.done.screens++;
    expect(findings.unknown()).toEqual([]);
  });
}
