import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { expect, test, vi } from "vitest";

import type { RefusalFix } from "../api/client";
import { LockedAction } from "./LockedAction";

vi.mock("../i18n/context", () => ({
  useT: () => (key: string, ...args: (string | number)[]) => (args.length === 0 ? key : `${key}(${args.join("|")})`),
  usePendingLine: () => "sudo x agent grant --pending",
}));

function render(fix: RefusalFix, path?: string): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <LockedAction fix={fix} path={path} />
    </MemoryRouter>,
  );
}

// Critère B-6 : le droit et la machine viennent du fix de la réponse ; aucune
// table de clés de refus n'est lue. R-DROIT-8 (E03-07) : la ligne est la ligne
// constante, écrite par le serveur ; le droit se dit à côté, avec
// l'avertissement de ne coller aucune autre ligne.
test("un fix de droit montre la ligne que le serveur a jointe, le droit et l'avertissement", () => {
  const markup = render({ right: "docker.deploy", machine: "m1", command: "sudo y agent grant --pending" });
  expect(markup).toContain("sudo y agent grant --pending");
  expect(markup).toContain("anchor.run_command");
  expect(markup).toContain("rights.missing_right(docker.deploy)");
  expect(markup).toContain("rights.paste_only_pending");
  expect(markup).toContain("rights.paste_shows_change");
  expect(markup).not.toContain("reenroller");
});

test("sans ligne jointe, celle de la session ; le droit et le chemin se disent à côté, jamais dedans", () => {
  const markup = render({ right: "files.write", machine: "m2" }, "/srv/restore");
  expect(markup).toContain("sudo x agent grant --pending<");
  expect(markup).toContain("machine.grant_path(/srv/restore)");
  expect(markup).not.toContain("grant files.write");
});

test("short : la ligne seule, tronquée, entière dans l'infobulle avec l'avertissement", () => {
  const markup = renderToStaticMarkup(
    <MemoryRouter>
      <LockedAction fix={{ right: "restic.verify", machine: "m4" }} short />
    </MemoryRouter>,
  );
  expect(markup).toContain("token-box-short");
  expect(markup).toContain('title="anchor.run_command sudo x agent grant --pending rights.missing_right(restic.verify) rights.paste_only_pending rights.paste_shows_change"');
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

// ARB-1 : un droit manquant offre « Demander ce droit à la machine » à côté
// de la ligne constante ; une ligne étroite garde la ligne seule.
test("TestARB1_ALockedGestureOffersToRequestTheRight", () => {
  expect(render({ right: "docker.deploy", machine: "m1" })).toContain("rights.request_right");
  const short = renderToStaticMarkup(
    <MemoryRouter>
      <LockedAction fix={{ right: "docker.deploy", machine: "m1" }} short />
    </MemoryRouter>,
  );
  expect(short).not.toContain("rights.request_right");
  expect(render({ command: "sudo x agent trust list", machine: "m3" })).not.toContain("rights.request_right");
});
