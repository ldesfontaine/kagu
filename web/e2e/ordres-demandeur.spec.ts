import { label } from "./support/catalog";
import { expect, test } from "./support/findings";

// L'historique des ordres (essai E00-01), sur les données fictives : les
// ordres de vps-paris-1 ont été demandés par la session du banc. L'ordre
// enregistre et signe la session (A2 §5) ; « Demandé par » nomme le compte.

const remoteMachine = "11111111-2222-4333-8444-555555555555";
const benchSession = "5e55105e55105e55";

test("« Demandé par » nomme le compte, jamais la session", async ({ page, findings }) => {
  findings.where = `/machines/${remoteMachine}/agent`;
  await page.goto(`/machines/${remoteMachine}/agent`);
  const orders = page.locator("section.card").filter({ has: page.locator(".card-t", { hasText: new RegExp(`^${label("action.title")}$`) }) });
  await expect(orders.locator("thead th").last()).toHaveText(label("action.col_by"));
  const requesters = orders.locator("tbody tr td:last-child");
  await expect(requesters.filter({ hasText: /^lucas$/ }).first()).toBeVisible();
  await expect(orders).not.toContainText(benchSession);
});
