import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { expect, test, vi } from "vitest";

import type { RefusalFix } from "../api/client";
import { LockedAction } from "./LockedAction";

vi.mock("../i18n/context", () => ({
  useT: () => (key: string, ...args: (string | number)[]) => (args.length === 0 ? key : `${key}(${args.join("|")})`),
}));

function render(fix: RefusalFix, path?: string): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <LockedAction fix={fix} path={path} />
    </MemoryRouter>,
  );
}

// Critère B-6 : le droit et la machine viennent du fix de la réponse ; aucune
// table de clés de refus n'est lue. Le geste reste « Ré-enrôler » jusqu'à T03-03.
test("un fix de droit mène au ré-enrôlement de la machine qu'il nomme", () => {
  const markup = render({ right: "docker.deploy", machine: "m1", command: "sudo x agent grant docker.deploy" });
  expect(markup).toContain('href="/machines/m1/reenroller?droit=docker.deploy"');
  expect(markup).toContain("machine.reenroll_with(machine.capability_docker_deploy)");
  expect(render({ right: "files.write", machine: "m2" }, "/srv/restore")).toContain('href="/machines/m2/reenroller?droit=files.write&amp;chemin=%2Fsrv%2Frestore"');
});

test("un fix d'ancre montre la commande ; sans rien à lever, rien", () => {
  const markup = render({ command: "sudo x agent trust list", machine: "m3" });
  expect(markup).toContain("sudo x agent trust list");
  expect(markup).toContain('href="/machines/m3/agent"');
  expect(render({})).toBe("");
  // Un droit sans machine ne mène nulle part.
  expect(render({ right: "docker.deploy" })).toBe("");
});
