import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, test, vi } from "vitest";

import type { TokenResponse } from "../../api/machines";
import { EnrollmentToken } from "./EnrollmentToken";

vi.mock("../../i18n/context", () => ({ useT: () => (key: string) => key }));

// Chaque bloc copiable rendu : ce qu'il montre et ce que son bouton copie.
const boxes: { value: string; copy: string }[] = [];

vi.mock("../../components/Copy", () => ({
  TokenBox: ({ value, copy }: { value: string; copy?: string }) => {
    boxes.push({ value, copy: copy ?? value });
    return <code>{value}</code>;
  },
}));

beforeEach(() => {
  boxes.length = 0;
});

const command = "curl -fsSL https://example.org/install.sh | sudo sh -s -- join --server https://kagu.example.org --server-key SHA256:abc --rights manage";

const token: TokenResponse = {
  id: "0123456789abcdef",
  name: "web-1",
  token: "kg_secret",
  set: "manage",
  command,
  reenroll_lines: [],
  expires_at: new Date(Date.now() + 3_480_000).toISOString(),
};

// B1 §3 : un seul « Copier », qui prend deux lignes, la commande puis le jeton.
test("un seul bouton Copier, qui copie la commande puis le jeton", () => {
  renderToStaticMarkup(<EnrollmentToken token={token} />);
  expect(boxes).toEqual([{ value: command, copy: `${command}\nkg_secret\n` }]);
});

test("la commande ne porte pas le jeton ; il se montre à part, avec sa durée et la phrase du collage", () => {
  const markup = renderToStaticMarkup(<EnrollmentToken token={token} />);
  expect(boxes[0]?.value).not.toContain("kg_secret");
  expect(markup).toContain("machine.join_token");
  expect(markup).toContain("kg_secret");
  expect(markup).toContain("machine.token_once");
  expect(markup).toContain("machine.join_paste");
  expect(markup).not.toContain("machine.join_reenroll_first");
});

test("un ré-enrôlement montre d'abord les deux commandes qui retirent l'agent en place, une par ligne, sans enchaînement", () => {
  const reenrollLines = ["sudo systemctl stop kagu-agent", "sudo rm -f /var/lib/kagu-agent/identity.json"];
  const markup = renderToStaticMarkup(<EnrollmentToken token={{ ...token, reenroll_lines: reenrollLines }} />);
  expect(markup).toContain("machine.join_reenroll_first");
  expect(boxes.map((box) => box.value)).toEqual([reenrollLines.join("\n"), command]);
  expect(boxes[0]?.value).not.toContain("&&");
  expect(boxes[1]?.copy).toBe(`${command}\nkg_secret\n`);
});

// ARB-4 : la ligne d'ajout porte sa note (l'adresse des versions, à comparer
// à la documentation), et pas l'avertissement des lignes de l'agent.
test("la ligne d'ajout porte sa note, pas l'avertissement des lignes de droits", () => {
  const markup = renderToStaticMarkup(<EnrollmentToken token={token} />);
  expect(markup).toContain("machine.join_line_check");
  expect(markup).not.toContain("rights.paste_only_pending");
});
