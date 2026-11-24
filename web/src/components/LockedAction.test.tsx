import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { expect, test, vi } from "vitest";

import type { RefusalFix } from "../api/client";
import { LockedAction } from "./LockedAction";

vi.mock("../i18n/context", () => ({
  useT: () => (key: string, ...args: (string | number)[]) => (args.length === 0 ? key : `${key}(${args.join("|")})`),
  useGrantLine: (right: string) => `sudo x agent grant ${right}`,
}));

function render(fix: RefusalFix, path?: string): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <LockedAction fix={fix} path={path} />
    </MemoryRouter>,
  );
}

// Critère B-6 : le droit et la machine viennent du fix de la réponse ; aucune
// table de clés de refus n'est lue. T03-03 : le geste est la ligne grant,
// écrite par le serveur, plus le ré-enrôlement.
test("un fix de droit montre la ligne grant que le serveur a jointe", () => {
  const markup = render({ right: "docker.deploy", machine: "m1", command: "sudo y agent grant docker.deploy" });
  expect(markup).toContain("sudo y agent grant docker.deploy");
  expect(markup).toContain("anchor.run_command");
  expect(markup).toContain("machine.grant_shows_change");
  expect(markup).not.toContain("reenroller");
});

test("sans ligne jointe, celle de la session ; le chemin se dit à côté, jamais dedans", () => {
  const markup = render({ right: "files.write", machine: "m2" }, "/srv/restore");
  expect(markup).toContain("sudo x agent grant files.write<");
  expect(markup).toContain("machine.grant_path(/srv/restore)");
  expect(markup).not.toContain("files.write=");
});

test("short : la ligne seule, tronquée, entière dans l'infobulle", () => {
  const markup = renderToStaticMarkup(
    <MemoryRouter>
      <LockedAction fix={{ right: "restic.verify", machine: "m4" }} short />
    </MemoryRouter>,
  );
  expect(markup).toContain("token-box-short");
  expect(markup).toContain('title="anchor.run_command sudo x agent grant restic.verify machine.grant_shows_change"');
  expect(markup).not.toContain("<p");
});

test("un fix d'ancre montre la commande ; sans rien à lever, rien", () => {
  const markup = render({ command: "sudo x agent trust list", machine: "m3" });
  expect(markup).toContain("sudo x agent trust list");
  expect(markup).toContain('href="/machines/m3/agent"');
  expect(render({})).toBe("");
  // Un droit sans machine ne mène nulle part.
  expect(render({ right: "docker.deploy" })).toBe("");
});
