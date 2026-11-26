import { expect, test } from "vitest";

import type { AgentAnchors } from "../api/machines";
import { anchorKinds, anchorKindsFor, anchorLabelKey, anchorOfReason, blockingAnchors } from "./anchors";

// La réponse figée de la fiche d'une machine (internal/edge/server/testdata) : le
// registre du serveur y est écrit, type par type.
const goldenFile = import.meta.glob<string>("../../../internal/edge/server/testdata/machine.golden.json", { eager: true, import: "default", query: "?raw" });

test("les types d'ancre du front sont ceux du registre du serveur, dans son ordre", () => {
  const golden = JSON.parse(Object.values(goldenFile)[0] ?? "{}") as { agent: { anchors: AgentAnchors } };
  expect(golden.agent.anchors.kinds.map((kind) => ({ name: kind.name, right: kind.right, max: kind.max }))).toEqual(anchorKinds.map((kind) => ({ ...kind })));
});

test("les clés du catalogue d'un type suivent son nom", () => {
  expect(anchorLabelKey("restic.target-cert")).toBe("anchor.label_restic_target_cert");
});

test("seules les ancres des droits portés comptent", () => {
  expect(anchorKindsFor(["probe.lan"]).map((kind) => kind.name)).toEqual([]);
  expect(anchorKindsFor(["backup.produce"]).map((kind) => kind.name)).toEqual(["backup.recipient", "backup.guest"]);
  expect(anchorKindsFor(["restic.produce"]).map((kind) => kind.name)).toEqual(["restic.target-cert"]);
});

const reported: AgentAnchors = {
  reported: true,
  kinds: [
    { name: "backup.recipient", right: "backup.produce", max: 2, state: "set", values: ["age1key"] },
    { name: "backup.guest", right: "backup.produce", max: 32, state: "none", values: [] },
    { name: "restic.target-cert", right: "restic.produce", max: 4, state: "unreadable", values: [] },
  ],
};

test("deux états distincts bloquent un ordre : aucune posée, illisibles", () => {
  expect(blockingAnchors(reported, ["backup.produce", "restic.produce"]).map((kind) => `${kind.name}:${kind.state}`)).toEqual(["backup.guest:none", "restic.target-cert:unreadable"]);
  // Sans le droit coché, l'ancre ne bloque rien.
  expect(blockingAnchors(reported, ["observe"])).toEqual([]);
  // Un agent d'avant les ancres ne les applique pas : rien ne bloque.
  expect(blockingAnchors({ reported: false, kinds: reported.kinds }, ["backup.produce"])).toEqual([]);
});

test("une raison d'ordre refusé par une ancre nomme son type", () => {
  expect(anchorOfReason("anchor_outside:backup.guest")).toEqual({ why: "outside", name: "backup.guest" });
  expect(anchorOfReason("anchor_missing:restic.target-cert")).toEqual({ why: "missing", name: "restic.target-cert" });
  expect(anchorOfReason("right_missing:backup.produce")).toBeNull();
  expect(anchorOfReason("anchor_missing")).toBeNull();
});
