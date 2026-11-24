import { useState } from "react";

import { login } from "../api/auth";
import { failureOf } from "../api/client";
import { Card, CardHeader } from "../components/Card";
import { Field, Input } from "../components/Field";
import { FormActions, FormBody } from "../components/FormBody";
import { useAction } from "../hooks/useAction";
import { useForm } from "../hooks/useForm";
import { useServerTime } from "../hooks/useServerTime";
import { useT } from "../i18n/context";
import { asksTOTP, loginFailure } from "../lib/auth";
import { AccessPage } from "./AccessPage";

// La connexion native : nom, mot de passe, « Se connecter ». Quand le code à
// six chiffres est actif, le serveur le demande après un mot de passe juste,
// et un second écran le saisit (R-A2-6). Le serveur pose le cookie de la
// session avec sa réponse ; la porte relit alors l'accès et ouvre
// l'interface. Le refus ne dit jamais lequel du nom ou du mot de passe est faux.
// L'écran du code dit l'heure du serveur : un téléphone qui ne dit pas la
// même explique un code refusé, sans que le refus en dise rien.
export function Login({ onSignedIn }: { onSignedIn: () => void }) {
  const t = useT();
  const action = useAction();
  const { values, change } = useForm({ username: "", password: "", code: "" });
  const [codeScreen, setCodeScreen] = useState(false);
  const serverTime = useServerTime();

  const signIn = () => {
    action.run(
      async () => {
        try {
          return await login(values.username, values.password, codeScreen ? values.code : "");
        } catch (failure) {
          if (asksTOTP(failureOf(failure))) {
            setCodeScreen(true);
          }
          throw failure;
        }
      },
      { onDone: onSignedIn },
    );
  };

  return (
    <AccessPage narrow>
      <Card>
        <CardHeader title={t(codeScreen ? "auth.login_code_title" : "auth.login_title")} />
        <FormBody
          onSubmit={signIn}
          error={loginFailure(action.error)}
          actions={
            <>
              <FormActions submitLabel={t("auth.login")} submitIcon="shield" busy={action.busy} />
              <p className="secondary">{t(codeScreen ? "auth.totp_rescue" : "auth.login_rescue")}</p>
            </>
          }
        >
          {codeScreen ? (
            <Field label={t("auth.totp_code_label")} htmlFor="auth-code" help={serverTime === undefined ? t("auth.login_code_intro") : `${t("auth.login_code_intro")} ${serverTime}`}>
              <Input
                id="auth-code"
                type="text"
                mono
                value={values.code}
                onChange={(event) => change("code", event.target.value)}
                inputMode="numeric"
                maxLength={6}
                autoComplete="one-time-code"
                autoFocus
                required
              />
            </Field>
          ) : (
            <>
              <Field label={t("auth.username_label")} htmlFor="auth-username">
                <Input id="auth-username" type="text" value={values.username} onChange={(event) => change("username", event.target.value)} maxLength={64} autoComplete="username" required />
              </Field>
              <Field label={t("auth.password_label")} htmlFor="auth-password">
                <Input id="auth-password" type="password" value={values.password} onChange={(event) => change("password", event.target.value)} autoComplete="current-password" required />
              </Field>
            </>
          )}
        </FormBody>
      </Card>
    </AccessPage>
  );
}
