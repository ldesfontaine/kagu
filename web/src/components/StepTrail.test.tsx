import { renderToStaticMarkup } from "react-dom/server";
import { expect, test, vi } from "vitest";

import type { Step } from "../lib/steps";
import { StepTrail } from "./StepTrail";

// Le catalogue des clés d'étape que TestR_GESTE_4_TerminalAndScreenShowTheSameLabel
// (internal/kit/step) écrit depuis internal/kit/lang, après les marqueurs
// remplacés : ce que /api/i18n sert, et ce que step.Print imprime.
const goldens = import.meta.glob<Record<string, Record<string, string>>>("../../../internal/kit/step/testdata/labels.golden.json", { eager: true, import: "default" });
const labels = Object.values(goldens)[0] ?? {};
const french = labels.fr ?? {};

vi.mock("../i18n/context", () => ({
  useT: () => (key: string) => french[key] ?? key,
}));

// renderToStaticMarkup échappe le texte : on compare à la forme échappée.
function escaped(text: string): string {
  return text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#x27;");
}

function render(steps: Step[]): string {
  return renderToStaticMarkup(<StepTrail steps={steps} />);
}

const at = "2026-11-25T10:00:00Z";

// R-GESTE-4 : pour chaque clé déclarée, l'écran montre le libellé que le
// terminal imprime.
test("R-GESTE-4 : chaque clé déclarée s'affiche avec le libellé du terminal", () => {
  const keys = Object.keys(french);
  expect(keys.length).toBeGreaterThan(0);
  for (const key of keys) {
    const markup = render([{ key, state: "done", at }]);
    expect(markup).toContain(escaped(french[key] ?? ""));
    expect(markup).not.toContain(`>${key}<`);
  }
});

test("les étapes gardent leur ordre, leur état et leur détail en texte brut", () => {
  const markup = render([
    { key: "step.enroll.system", state: "done", detail: "Debian 12, amd64", at },
    { key: "step.enroll.docker", state: "failed", detail: "<script>alert(1)</script>", at },
    { key: "step.enroll.restic", state: "skipped", at },
    { key: "step.enroll.account", state: "running", at },
  ]);
  const order = ["step.enroll.system", "step.enroll.docker", "step.enroll.restic", "step.enroll.account"].map((key) => markup.indexOf(escaped(french[key] ?? key)));
  expect(order.every((index, position) => index >= 0 && (position === 0 || index > (order[position - 1] ?? 0)))).toBe(true);
  expect(markup).toContain("step-trail-danger");
  expect(markup).toContain("step_trail.state_skipped");
  expect(markup).toContain("step_trail.state_running");
  expect(markup).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  expect(markup).not.toContain("<script>");
});
