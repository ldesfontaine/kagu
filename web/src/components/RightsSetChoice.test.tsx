import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { expect, test, vi } from "vitest";

import type { JoinSet } from "../api/machines";
import { RightsSetChoice } from "./RightsSetChoice";

vi.mock("../i18n/context", () => ({ useT: () => (key: string) => key }));

// Les trois jeux, tels que GET /api/machines les rend (join.sets).
const sets: JoinSet[] = [
  { set: "observe", groups: [{ name: "see", rights: ["observe", "probe.lan"] }] },
  {
    set: "manage",
    groups: [
      { name: "see", rights: ["observe", "probe.lan"] },
      { name: "deploy", rights: ["docker.deploy", "docker.update"] },
      { name: "enter", rights: [] },
    ],
  },
  {
    set: "root",
    groups: [
      { name: "deploy", rights: ["docker.deploy", "terminal.container"] },
      { name: "enter", rights: ["terminal.host"] },
    ],
  },
];

const dottedNames = ["probe.lan", "docker.deploy", "docker.update", "terminal.container", "terminal.host"];

function render(value: JoinSet["set"] | ""): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <RightsSetChoice sets={sets} value={value} onChange={() => undefined} />
    </MemoryRouter>,
  );
}

// Le texte lisible plis fermés : tout, sauf le contenu des « Voir le détail ».
function visibleWhileFolded(markup: string): string {
  return markup.replace(/<div class="fold-body">[\s\S]*?<\/details>/g, "");
}

// B1 §8, R-A3-13 : l'écran « Ajouter une machine » montre trois cartes,
// chacune avec sa phrase ; aucun nom de droit n'est visible tant que « Voir
// le détail » est fermé.
test("TestR_A3_13_AddMachineShowsSetsNotRights : trois cartes, aucun nom de droit hors du détail", () => {
  const markup = render("manage");
  for (const key of ["rights.observe", "rights.manage", "rights.root", "rights.observe_hint", "rights.manage_risk", "rights.root_risk"]) {
    expect(markup).toContain(key);
  }
  expect(markup.match(/type="radio"/g)?.length).toBe(3);
  expect(markup).not.toContain('type="checkbox"');
  expect(markup.match(/rights\.see_detail/g)?.length).toBe(3);
  expect(markup).not.toMatch(/<details[^>]* open/);
  const folded = visibleWhileFolded(markup);
  for (const name of dottedNames) {
    expect(folded).not.toContain(name);
  }
  // Ouvert, le détail les groupe comme l'onglet Droits.
  expect(markup).toContain("rights.group_deploy");
  expect(markup).toContain('<code class="mono">docker.deploy</code>');
});

test("un groupe que le jeu n'ouvre pas ne se montre pas dans son détail", () => {
  const manageDetail = render("").split("rights.manage_risk")[1]?.split("rights.root")[0] ?? "";
  expect(manageDetail).toContain("rights.group_deploy");
  expect(manageDetail).not.toContain("rights.group_enter");
});

test("le jeu choisi est coché, aucun sans choix", () => {
  expect(render("").match(/checked=""/g)).toBeNull();
  expect(render("root").match(/checked=""/g)?.length).toBe(1);
});
