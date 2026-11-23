import { renderToStaticMarkup } from "react-dom/server";
import { expect, test, vi } from "vitest";

import { ApiError } from "../api/client";
import { reauthThenPerform, type Confirm, type ReauthConfirm } from "../lib/confirmGesture";
import { ConfirmGesture } from "./ConfirmGesture";

// Sans serveur, la traduction rend la clé.
vi.mock("../i18n/context", () => ({ useT: () => (key: string) => key }));

function render(confirm: Confirm): string {
  return renderToStaticMarkup(
    <ConfirmGesture confirm={confirm} title="titre" question="question" confirmLabel="Confirmer" perform={() => Promise.resolve()} onDone={() => undefined} onClose={() => undefined} />,
  );
}

const native: ReauthConfirm = { mode: "reauth", sso: false, code: false };
const withCode: ReauthConfirm = { mode: "reauth", sso: false, code: true };
const sso: ReauthConfirm = { mode: "reauth", sso: true, code: false };

test("en native, la fenêtre redemande le mot de passe, sans code quand il n'est pas actif", () => {
  const markup = render(native);
  expect(markup).toContain('id="reauth-password"');
  expect(markup).not.toContain('id="reauth-code"');
});

test("le code est demandé quand il est actif", () => {
  const markup = render(withCode);
  expect(markup).toContain('id="reauth-password"');
  expect(markup).toContain('id="reauth-code"');
});

test("en SSO, rien n'est demandé, la fenêtre le dit", () => {
  const markup = render(sso);
  expect(markup).toContain("auth.reauth_sso");
  expect(markup).not.toContain('id="reauth-password"');
  expect(markup).not.toContain('id="reauth-code"');
});

test("un mot de passe faux arrête tout : le geste ne part pas", async () => {
  const perform = vi.fn(() => Promise.resolve());
  const refused = new ApiError(403, "auth.current_password_wrong");
  const send = vi.fn(() => Promise.reject(refused));
  await expect(reauthThenPerform(native, { password: "faux", code: "" }, send, perform)).rejects.toBe(refused);
  expect(perform).not.toHaveBeenCalled();
});

test("un mot de passe juste redonne la preuve, puis le geste part", async () => {
  const order: string[] = [];
  const send = vi.fn(() => {
    order.push("reauth");
    return Promise.resolve();
  });
  const perform = vi.fn(() => {
    order.push("geste");
    return Promise.resolve();
  });
  await reauthThenPerform(native, { password: "juste", code: "123456" }, send, perform);
  expect(send).toHaveBeenCalledWith("juste", "");
  expect(order).toEqual(["reauth", "geste"]);
});

test("le code part avec le mot de passe quand il est actif", async () => {
  const send = vi.fn(() => Promise.resolve());
  await reauthThenPerform(withCode, { password: "juste", code: "123456" }, send, () => Promise.resolve());
  expect(send).toHaveBeenCalledWith("juste", "123456");
});

test("en SSO, rien n'est redemandé : le geste part seul", async () => {
  const send = vi.fn(() => Promise.resolve());
  const perform = vi.fn(() => Promise.resolve());
  await reauthThenPerform(sso, { password: "", code: "" }, send, perform);
  expect(send).not.toHaveBeenCalled();
  expect(perform).toHaveBeenCalledOnce();
});

test("un mode qui n'est pas encore branché ne s'affiche pas en silence", () => {
  expect(() => render({ mode: "click" })).toThrow(/not wired/);
});
