import { renderToStaticMarkup } from "react-dom/server";
import { expect, test, vi } from "vitest";

import type { Step } from "../../lib/steps";
import { AgentWait } from "./EnrollFlow";

vi.mock("../../i18n/context", () => ({
  useT:
    () =>
    (key: string, ...args: unknown[]) =>
      [key, ...args].join(" "),
}));

const expiresAt = "2026-11-27T12:00:00Z";

// R-B1-11, R-GESTE-4 : la tuile « en cours d'arrivée » dessine les étapes que
// le serveur rend pour le jeton, dans son ordre, sans en connaître la liste.
test("la tuile d'arrivée dessine la frise lue sur le jeton", () => {
  const steps: Step[] = [
    { key: "step.enroll.system", state: "done", detail: "Debian 12, amd64", at: "2026-11-27T11:00:00Z" },
    { key: "step.enroll.account", state: "done", at: "2026-11-27T11:00:05Z" },
    { key: "step.enroll.enrolled", state: "running", at: "2026-11-27T11:00:09Z" },
  ];
  const markup = renderToStaticMarkup(<AgentWait name="vps-1" progress={{ state: "waiting", steps }} expiresAt={expiresAt} remaining={60_000} />);
  expect(markup).toContain("step-trail");
  const order = steps.map((one) => markup.indexOf(`>${one.key}<`));
  expect(order.every((index, position) => index >= 0 && (position === 0 || index > (order[position - 1] ?? 0)))).toBe(true);
  expect(markup).toContain("Debian 12, amd64");
  expect(markup).toContain("machine.wait_pending vps-1");
});

test("un jeton expiré se dit avec l'heure, et la tentative refusée reste dans la frise", () => {
  const refused: Step = { key: "step.enroll.enrolled", state: "failed", detail: "token_expired", at: "2026-11-27T12:05:00Z" };
  const markup = renderToStaticMarkup(<AgentWait name="vps-1" progress={{ state: "expired", steps: [refused] }} expiresAt={expiresAt} remaining={-300_000} />);
  expect(markup).toMatch(/machine\.wait_expired \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/);
  expect(markup).toContain("step-trail-danger");
  expect(markup).toContain("token_expired");
});

test("rien de coché, pas de frise vide", () => {
  const markup = renderToStaticMarkup(<AgentWait name="vps-1" progress={{ state: "waiting", steps: [] }} expiresAt={expiresAt} remaining={60_000} />);
  expect(markup).not.toContain("step-trail");
});
