import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { expect, test, vi } from "vitest";

import type { AgentRights, RightsGroup } from "../api/machines";
import { RightsList } from "./RightsList";

vi.mock("../i18n/context", () => ({
  useT: () => (key: string, ...args: (string | number)[]) => (args.length === 0 ? key : `${key}(${args.join("|")})`),
}));

function group(over: Partial<RightsGroup>): RightsGroup {
  return { name: "see", state: "ok", until: null, worth_root: false, host_terminal: false, rights: [], grant_line: "", revoke_line: "", ...over };
}

// Une machine en « Gérer » qui a aussi terminal.host, jusqu'à une heure.
const rights: AgentRights = {
  set: "manage",
  set_lines: [
    { set: "observe", line: "sudo kagu agent grant --set observe" },
    { set: "root", line: "sudo kagu agent grant --set root" },
  ],
  root_here: false,
  groups: [
    group({ name: "see", rights: [{ name: "observe", paths: [], state: "ok", until: null }], revoke_line: "" }),
    group({ name: "deploy", worth_root: true, rights: [{ name: "docker.deploy", paths: [], state: "ok", until: null }], revoke_line: "sudo kagu agent revoke docker.deploy" }),
    group({ name: "backup", state: "missing", rights: [{ name: "restic.produce", paths: [], state: "missing", until: null }], grant_line: "sudo kagu agent grant --pending" }),
    group({
      name: "enter",
      host_terminal: true,
      until: "2026-11-25T16:42:00Z",
      rights: [{ name: "terminal.host", paths: ["root"], state: "ok", until: "2026-11-25T16:42:00Z" }],
      revoke_line: "sudo kagu agent revoke terminal.host",
    }),
    group({ name: "network", state: "missing", rights: [{ name: "network.private", paths: [], state: "missing", until: null }], grant_line: "sudo kagu agent grant --pending" }),
  ],
};

function render(shown: AgentRights): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <RightsList rights={shown} machineName="vps-1" now={Date.parse("2026-11-25T12:00:00Z")} />
    </MemoryRouter>,
  );
}

// Le texte lisible pli fermé : tout, sauf le contenu des « Voir le détail »
// et les lignes à coller (un nom de droit n'y est permis que là, G-17). Les
// clés du catalogue (rights.observe…) sont des libellés, pas des noms.
function visibleWhileFolded(markup: string): string {
  return markup
    .replace(/<div class="fold-body">[\s\S]*?<\/details>/g, "")
    .replace(/<div class="token-box[^"]*"[^>]*><code class="mono">[^<]*<\/code>/g, "")
    .replace(/rights\.[a-z_]+/g, "");
}

// R-A3-13 : à l'écran, le jeu et cinq groupes ; aucun nom de droit visible tant
// que « Voir le détail » est fermé, hors des lignes à copier.
test("TestR_A3_13_RightsAreGroupedNeverFlat : aucun nom de droit hors du détail", () => {
  const markup = render(rights);
  for (const name of ["see", "deploy", "backup", "enter", "network"]) {
    expect(markup).toContain(`rights.group_${name}_hint`);
  }
  expect(markup).toContain("rights.manage_risk");
  const folded = visibleWhileFolded(markup);
  for (const name of ["observe", "docker.deploy", "restic.produce", "terminal.host", "network.private"]) {
    expect(folded).not.toContain(name);
  }
  expect(markup).not.toMatch(/<details[^>]* open/);
  expect(markup).toContain("<code class=\"mono\">terminal.host</code>");
});

// R-A3-12 (N-M6) : sous Entrer, la phrase du terminal sur la machine quand
// terminal.host est posé ; rien sans lui. « vaut root » sur Déployer.
test("TestR_A3_12_HostTerminalRiskShownWhenTerminalHostIsSet", () => {
  expect(render(rights)).toContain("rights.host_terminal_risk");
  expect(render(rights)).toContain("rights.worth_root_why");
  const without = { ...rights, groups: rights.groups.map((shown) => ({ ...shown, host_terminal: false, worth_root: false })) };
  expect(render(without)).not.toContain("rights.host_terminal_risk");
  expect(render(without)).not.toContain("rights.worth_root");
});

// R-DROIT-3 : les lignes sont celles du serveur, telles quelles, chacune avec
// ce qu'elle fera ; la coche dit « permis jusqu'à » une échéance.
test("les lignes viennent du serveur et la coche porte l'échéance", () => {
  const markup = render(rights);
  for (const line of ["sudo kagu agent grant --set observe", "sudo kagu agent grant --set root", "sudo kagu agent grant --pending", "sudo kagu agent revoke terminal.host"]) {
    expect(markup).toContain(line);
  }
  expect(markup.match(/rights\.paste_shows_change/g)?.length).toBe(6);
  // R-DROIT-8 (E03-07) : sous chaque ligne d'un groupe pas permis,
  // l'avertissement de ne coller aucune autre ligne.
  expect(markup.match(/rights\.paste_only_pending/g)?.length).toBe(2);
  expect(markup).toContain("rights.allowed_until(");
  expect(markup).toContain("rights.not_allowed");
  expect(markup).not.toContain("rights.root_here");
  expect(render({ ...rights, root_here: true, set: "root" })).toContain("rights.root_here(vps-1)");
  expect(render({ ...rights, set: "" })).toContain("rights.custom_hint");
});
