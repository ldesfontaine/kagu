import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { expect, test, vi } from "vitest";

import { ApiError } from "../api/client";
import { Failure } from "./Failure";

vi.mock("../i18n/context", () => ({
  useT: () => (key: string, ...args: (string | number)[]) => (args.length === 0 ? key : `${key}(${args.join("|")})`),
  useGrantLine: (right: string) => `sudo x agent grant ${right}`,
}));

function render(error: ApiError | string | null, gesture?: Parameters<typeof Failure>[0]["gesture"]): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <Failure error={error} gesture={gesture} />
    </MemoryRouter>,
  );
}

test("une erreur ordinaire se dit en note, sans geste", () => {
  const markup = render(new ApiError(422, "probe.target_invalid"));
  expect(markup).toContain("probe.target_invalid");
  expect(markup).not.toContain("<a ");
});

test("un refus de droit porte le geste que le serveur joint, sans table", () => {
  const refused = new ApiError(409, "backup.right_missing", { error: "backup.right_missing", fix: { right: "backup.receive", machine: "m7", command: "sudo x agent grant backup.receive" } });
  const markup = render(refused, { machineID: "m-autre", path: "/srv/backups" });
  expect(markup).toContain("backup.right_missing");
  // La ligne est celle du serveur ; le chemin, celui de l'écran, se dit à côté.
  expect(markup).toContain("sudo x agent grant backup.receive<");
  expect(markup).toContain("machine.grant_path(/srv/backups)");
  // Sans fix, la clé seule ne mène nulle part : le front ne la traduit pas en droit.
  expect(render(new ApiError(409, "backup.right_missing"), { machineID: "m7" })).not.toContain("<a ");
});

test("sans valeur connue, la commande est « trust list » et un lien mène à la fiche, onglet Agent", () => {
  const refused = new ApiError(409, "anchor.restic_target_cert_missing", { fix: { command: "sudo x agent trust list" } });
  const markup = render(refused, { machineID: "m3" });
  expect(markup).toContain("sudo x agent trust list");
  expect(markup).toContain('href="/machines/m3/agent"');
  expect(render(new ApiError(409, "a", { fix: { command: "sudo x agent trust add a b", exact: true } }), { machineID: "m3" })).not.toContain("<a ");
});

test("un refus par ancre locale montre la commande à lancer en root sur la machine", () => {
  const refused = new ApiError(409, "anchor.backup_guest_missing", { error: "anchor.backup_guest_missing", fix: { command: "sudo x agent trust add backup.guest 5012", exact: true } });
  const markup = render(refused);
  expect(markup).toContain("anchor.backup_guest_missing");
  expect(markup).toContain("anchor.run_command");
  expect(markup).toContain("sudo x agent trust add backup.guest 5012");
});
