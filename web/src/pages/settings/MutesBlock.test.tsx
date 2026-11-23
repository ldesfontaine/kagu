import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { expect, test, vi } from "vitest";

import type { Mute } from "../../api/alerts";
import { MutesBlock } from "./MutesBlock";

vi.mock("../../i18n/context", () => ({
  useT: () => (key: string, ...args: (string | number)[]) => (args.length === 0 ? key : `${key}(${args.join("|")})`),
  useI18n: () => ({ language: "fr" }),
}));

vi.mock("../../hooks/useAction", () => ({
  useAction: () => ({ run: () => {}, busy: false, error: null }),
}));

const sessionID = "5e55105e55105e55";
let mutes: Mute[] = [];

vi.mock("../../api/alerts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../api/alerts")>()),
  useMutes: () => ({ data: { mutes }, error: null, reload: () => {} }),
}));

function mute(over: Partial<Mute>): Mute {
  return {
    id: 1,
    kind: "",
    target: { kind: "", id: "", name: "" },
    reason: "mise à jour",
    starts_at: "2026-10-29T10:00:00Z",
    ends_at: "2099-10-29T11:00:00Z",
    active: true,
    created_by_kind: "operator",
    created_by_name: sessionID,
    created_by_label: "lucas",
    created_at: "2026-10-29T10:00:00Z",
    announce: false,
    public_title: "",
    ...over,
  };
}

function render(): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <MutesBlock />
    </MemoryRouter>,
  );
}

// Essai E00-01 : l'auteur d'un silence est le compte, jamais la session.
test("l'auteur d'un silence est le compte, pas la session", () => {
  mutes = [mute({})];
  const markup = render();
  expect(markup).toContain("audit.actor_operator · lucas");
  expect(markup).not.toContain(sessionID);
});

test("un silence d'avant, sans libellé, se lit comme avant", () => {
  mutes = [mute({ created_by_kind: "operator", created_by_name: "admin", created_by_label: "" })];
  expect(render()).toContain("audit.actor_operator · admin");
});
