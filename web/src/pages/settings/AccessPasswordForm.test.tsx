import { renderToStaticMarkup } from "react-dom/server";
import { expect, test, vi } from "vitest";

import { AccessPasswordForm } from "./AccessPasswordForm";

vi.mock("../../i18n/context", () => ({
  useT: () => (key: string, ...args: (string | number)[]) => (args.length === 0 ? key : `${key}(${args.join("|")})`),
}));

test("le formulaire demande le mot de passe actuel avant le nouveau", () => {
  const markup = renderToStaticMarkup(<AccessPasswordForm minLength={12} busy={false} onSubmit={() => {}} />);
  expect(markup).toContain("auth.current_label");
  expect(markup).toContain('id="auth-current"');
  expect(markup).toContain(`autoComplete="current-password"`);
  expect(markup.indexOf("auth-current")).toBeLessThan(markup.indexOf("auth-password"));
});
