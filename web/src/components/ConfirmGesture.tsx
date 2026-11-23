import { useState } from "react";

import { reauth } from "../api/auth";
import { useAction } from "../hooks/useAction";
import { useT } from "../i18n/context";
import { reauthThenPerform, type Confirm } from "../lib/confirmGesture";
import { Note } from "./Card";
import { ConfirmDialog } from "./ConfirmModal";
import { Failure } from "./Failure";
import { Field, Input } from "./Field";

// La fenêtre de confirmation d'un geste (brique B-4), bâtie sur ConfirmDialog
// et Modal. confirm dit ce qu'elle fait confirmer ; seul le mode « reauth »
// est branché. En native, elle redemande le mot de passe, et le code s'il est
// actif, puis lance le geste ; en SSO, elle ne demande rien et le dit. La
// fenêtre reste ouverte tant que le geste n'a pas abouti : un refus s'y
// affiche, onDone suit la réussite.
export function ConfirmGesture({
  confirm,
  title,
  question,
  confirmLabel,
  perform,
  onDone,
  onClose,
}: {
  confirm: Confirm;
  title: string;
  question: string;
  confirmLabel: string;
  perform: () => Promise<void>;
  onDone: () => void;
  onClose: () => void;
}) {
  const t = useT();
  const action = useAction();
  const [answer, setAnswer] = useState({ password: "", code: "" });
  if (confirm.mode !== "reauth") {
    throw new Error(`ConfirmGesture: mode ${confirm.mode} is not wired yet`);
  }
  const submit = () => {
    action.run(() => reauthThenPerform(confirm, answer, reauth, perform), { onDone });
  };

  return (
    <ConfirmDialog
      title={title}
      question={question}
      confirmLabel={confirmLabel}
      onConfirm={submit}
      onClose={onClose}
      stays
      busy={action.busy}
      dirty={answer.password !== "" || answer.code !== ""}
    >
      {confirm.sso ? (
        <Note tone="neutral">{t("auth.reauth_sso")}</Note>
      ) : (
        <>
          <Field label={t("auth.password_label")} htmlFor="reauth-password">
            <Input
              id="reauth-password"
              type="password"
              value={answer.password}
              onChange={(event) => setAnswer({ ...answer, password: event.target.value })}
              autoComplete="current-password"
              autoFocus
            />
          </Field>
          {confirm.code && (
            <Field label={t("auth.totp_code_label")} htmlFor="reauth-code">
              <Input
                id="reauth-code"
                type="text"
                mono
                value={answer.code}
                onChange={(event) => setAnswer({ ...answer, code: event.target.value })}
                inputMode="numeric"
                maxLength={6}
                autoComplete="one-time-code"
              />
            </Field>
          )}
        </>
      )}
      <Failure error={action.error} />
    </ConfirmDialog>
  );
}
