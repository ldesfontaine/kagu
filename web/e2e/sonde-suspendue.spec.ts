import { label } from "./support/catalog";
import { expect, test } from "./support/findings";

// E03-09 : pve-nord n'a pas probe.lan ; sa sonde « partage nas » vers le réseau
// local est suspendue, pas hors ligne. La liste la montre suspendue, sans la
// compter à traiter ; la fiche dit le droit qui manque et donne la ligne
// constante « grant --pending », jamais une ligne qui nomme le droit
// (R-DROIT-8). Aucune alerte ne la vise.

const probeName = "partage nas";

for (const theme of ["light", "dark"] as const) {
  test(`sonde suspendue, ${theme} : la pastille, le droit et la ligne constante`, async ({ page, findings }) => {
    findings.where = `/disponibilite/… (${theme})`;
    await page.addInitScript((value) => localStorage.setItem("theme", value), theme);

    await page.goto("/disponibilite");
    const row = page.locator("tr", { has: page.locator("a.svc", { hasText: probeName }) });
    await expect(row.locator(".pill")).toHaveText(label("probe.status_suspended"));
    await row.locator("a.svc").click();
    await expect(page).toHaveURL(/\/disponibilite\/[^/]+$/);
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);

    await expect(page.locator(".machine-state .pill")).toHaveText(label("probe.status_suspended"));
    const note = page.locator(".note", { hasText: label("probe.suspended_text") });
    await expect(note.locator(".token-box code")).toHaveText(/^sudo \S+ agent grant --pending$/);
    await expect(note).toContainText(label("rights.missing_right").replace("%s", "probe.lan"));
    for (const code of await page.locator(".token-box code").allInnerTexts()) {
      expect(code, "une ligne à coller qui nomme un droit").not.toMatch(/ agent grant [a-z]/);
    }
    await expect(page.getByText(label("probe.machine_offline"))).toHaveCount(0);
    findings.screens.push(`sonde-${theme}`);
    findings.done.screens++;

    const open = (await (await page.request.get("/api/alerts")).json()) as { alerts: { object: { name: string } }[] };
    expect(open.alerts.filter((alert) => alert.object.name === probeName)).toEqual([]);
    expect(findings.unknown()).toEqual([]);
  });
}
