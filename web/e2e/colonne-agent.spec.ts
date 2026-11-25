import { mkdirSync } from "node:fs";

import type { Page } from "@playwright/test";

import { label } from "./support/catalog";
import { expect, test } from "./support/findings";

// La colonne « Agent » de Machines, l'en-tête des agents en retard (R-B2-13)
// et le bandeau de version importée (T04-17), sur les données fictives. Le
// serveur du parcours pose chaque scène (e2e_agent_scene_test.go) : à jour,
// version importée au-dessus, agents en retard ; puis rend l'état d'avant.
// Avec E2E_CAPTURES=1, il laisse les captures T0417-* dans E2E_CAPTURES_DIR
// (par défaut, le dossier des captures du projet).

const captureFolder = process.env.E2E_CAPTURES_DIR ?? new URL("../../docs/projet/refonte-ux/captures/", import.meta.url).pathname;
const capturing = process.env.E2E_CAPTURES === "1";

interface MachineAnswer {
  id: string;
  name: string;
  agent: { version: string; behind: boolean; missing_kinds: string[] } | null;
}

async function playScene(page: Page, scene: "current" | "imported" | "behind" | "reset"): Promise<void> {
  const answer = await page.request.post("/__e2e/agent-update-scene", { data: { scene } });
  expect(answer.status(), `scène ${scene}`).toBe(204);
}

async function machines(page: Page): Promise<MachineAnswer[]> {
  const answer = (await (await page.request.get("/api/machines")).json()) as { machines: MachineAnswer[] };
  return answer.machines;
}

function format(key: string, ...values: (string | number)[]): string {
  let text = label(key);
  for (const value of values) {
    text = text.replace(/%[sd]/, String(value));
  }
  return text;
}

function kindLabel(kind: string): string {
  return label(`action.kind_${kind.split(".").join("_")}`);
}

function row(page: Page, name: string) {
  return page.locator("table tbody tr").filter({ has: page.getByRole("link", { name, exact: true }) });
}

const behindHeader = /^\d+ agents? à mettre à jour$/;
const importedBanner = /^v\d+\.\d+\.\d+ est importée\.$/;

test.afterAll(async ({ request }) => {
  await request.post("/__e2e/agent-update-scene", { data: { scene: "reset" } });
});

test("la colonne Agent, l'en-tête des agents en retard et le bandeau de version importée", async ({ page, findings }) => {
  findings.where = "/machines";
  await page.addInitScript(() => localStorage.setItem("theme", "light"));
  const local = (await machines(page)).find((machine) => machine.id === "local");
  expect(local).toBeDefined();
  const localName = local?.name ?? "";

  // À jour : la version seule, sans pastille ni ligne ; ni en-tête ni bandeau
  // (la seule version importée est celle qui tourne).
  await playScene(page, "current");
  await page.goto("/machines");
  const remote = row(page, "vps-paris-1");
  await expect(remote.locator(".tree-agent .num")).toHaveText("v0.0.1");
  await expect(remote.getByText(label("machines.agent_behind"), { exact: true })).toHaveCount(0);
  await expect(remote.locator(".tree-agent-missing")).toHaveCount(0);
  await expect(page.locator(".tree-agent-missing")).toHaveCount(0);
  await expect(page.getByText(behindHeader)).toHaveCount(0);
  await expect(page.getByText(importedBanner)).toHaveCount(0);

  // Une version importée au-dessus du serveur : le bandeau et sa ligne copiable.
  await playScene(page, "imported");
  await page.reload();
  const banner = page.locator(".card").filter({ has: page.getByText(format("machines.imported_ahead", "v0.0.2"), { exact: true }) });
  await expect(banner).toBeVisible();
  await expect(banner.locator(".token-box code")).toHaveText("sudo opencloud upgrade");
  await expect(page.getByText(behindHeader)).toHaveCount(0);
  await expect(page.locator(".pill-warn").filter({ hasText: label("machines.agent_behind") })).toHaveCount(0);

  // Les agents en retard : la pastille, ce qui manque (un genre ; deux nommés
  // et « et N autres »), l'infobulle qui les nomme tous, et l'en-tête.
  await playScene(page, "behind");
  await page.reload();
  const listed = await machines(page);
  const behind = listed.filter((machine) => machine.agent?.behind === true);
  expect(behind.length).toBeGreaterThan(1);

  await expect(remote.locator(".tree-agent .num")).toHaveText("v0.0.1");
  await expect(remote.locator(".pill-warn")).toHaveText(label("machines.agent_behind"));
  const remoteMissing = remote.locator(".tree-agent-missing");
  await expect(remoteMissing).toHaveText(format("machines.agent_missing", kindLabel("docker.deploy")));
  await expect(remoteMissing).toHaveAttribute("title", format("machines.agent_missing", kindLabel("docker.deploy")));

  const localKinds = listed.find((machine) => machine.id === "local")?.agent?.missing_kinds ?? [];
  expect(localKinds).toHaveLength(4);
  const localLabels = localKinds.map(kindLabel);
  const localRow = row(page, localName);
  await expect(localRow.locator(".pill-warn")).toHaveText(label("machines.agent_behind"));
  const localMissing = localRow.locator(".tree-agent-missing");
  await expect(localMissing).toHaveText(format("machines.agent_missing_more", localLabels.slice(0, 2).join(" · "), 2));
  await expect(localMissing).toHaveAttribute("title", format("machines.agent_missing", localLabels.join(" · ")));

  await expect(page.locator(".pill-warn").filter({ hasText: label("machines.agent_behind") })).toHaveCount(behind.length);
  await expect(page.getByText(format("machines.agents_behind", behind.length), { exact: true })).toBeVisible();
  await expect(page.locator(".card").filter({ has: page.getByText(format("machines.imported_ahead", "v0.0.3"), { exact: true }) }).locator(".token-box code")).toHaveText(
    "sudo opencloud upgrade",
  );
  findings.screens.push("/machines");
});

// Les captures de l'écran avec agents en retard et bandeau, clair et sombre.
for (const theme of ["light", "dark"] as const) {
  test(`captures de la colonne Agent et du bandeau, ${theme}`, async ({ page }) => {
    test.skip(!capturing, "captures demandées par E2E_CAPTURES=1");
    await page.setViewportSize({ width: 1500, height: 1000 });
    await page.addInitScript((value) => localStorage.setItem("theme", value), theme);
    await playScene(page, "behind");
    await page.goto("/machines");
    await expect(page.getByText(behindHeader)).toBeVisible();
    await expect(page.getByText(importedBanner)).toBeVisible();
    mkdirSync(captureFolder, { recursive: true });
    await page.waitForTimeout(250);
    await page.screenshot({ path: `${captureFolder}/T0417-machines-agents-${theme === "light" ? "clair" : "sombre"}.png`, fullPage: true });
  });
}
