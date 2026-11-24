import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { expect, test, vi } from "vitest";

import type { ActionRun } from "../api/actions";
import { ActionsCard } from "./ActionsCard";

vi.mock("../i18n/context", () => ({
  useT: () => (key: string, ...args: (string | number)[]) => (args.length === 0 ? key : `${key}(${args.join("|")})`),
  useI18n: () => ({ language: "fr" }),
}));

vi.mock("../hooks/useAction", () => ({
  useAction: () => ({ run: () => {}, busy: false, error: null }),
}));

const sessionID = "5e55105e55105e55";
let runs: ActionRun[] = [];

vi.mock("../api/actions", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../api/actions")>()),
  useMachineActions: () => ({ data: { runs }, error: null, reload: () => {} }),
}));

function run(over: Partial<ActionRun>): ActionRun {
  return {
    id: "run1",
    kind: "agent.ping",
    params: {},
    machine_id: "m1",
    machine_name: "vps",
    agent_id: "agt",
    service_id: null,
    state: "succeeded",
    reason: "",
    seq: 1,
    requested_by: `operator:${sessionID}`,
    requested_by_label: "lucas",
    requested_at: "2026-10-29T10:00:00Z",
    not_after: "2026-10-29T10:02:00Z",
    finished_at: "2026-10-29T10:00:01Z",
    output: [],
    ...over,
  };
}

function render(): string {
  return renderToStaticMarkup(
    <MemoryRouter>
      <ActionsCard machineID="m1" agent={null} />
    </MemoryRouter>,
  );
}

// Essai E00-01 : « Demandé par » nomme le compte, jamais la session que
// l'ordre a enregistrée et signée.
test("l'historique des ordres nomme le compte, pas la session", () => {
  runs = [run({})];
  const markup = render();
  expect(markup).toContain("lucas");
  expect(markup).not.toContain(sessionID);
});

test("un ordre d'avant, sans libellé, se lit comme avant", () => {
  runs = [run({ requested_by: "rule:backup", requested_by_label: "" })];
  expect(render()).toContain("rule:backup");
});
