import { login } from "../api/auth";
import { Card, CardHeader } from "../components/Card";
import { Field, Input } from "../components/Field";
import { FormActions, FormBody } from "../components/FormBody";
import { useAction } from "../hooks/useAction";
import { useForm } from "../hooks/useForm";
import { useT } from "../i18n/context";
import { loginFailure } from "../lib/auth";
import { AccessPage } from "./AccessPage";

// La connexion native : nom, mot de passe, « Se connecter ». Le serveur pose
// le cookie de la session avec sa réponse ; la porte relit alors l'accès et
// ouvre l'interface. Le refus ne dit jamais lequel des deux est faux.
export function Login({ onSignedIn }: { onSignedIn: () => void }) {
  const t = useT();
  const action = useAction();
  const { values, change } = useForm({ username: "", password: "" });

  const signIn = () => {
    action.run(() => login(values.username, values.password), { onDone: onSignedIn });
  };

  return (
    <AccessPage narrow>
      <Card>
        <CardHeader title={t("auth.login_title")} />
        <FormBody
          onSubmit={signIn}
          error={loginFailure(action.error)}
          actions={
            <>
              <FormActions submitLabel={t("auth.login")} submitIcon="shield" busy={action.busy} />
              <p className="secondary">{t("auth.login_rescue")}</p>
            </>
          }
        >
          <Field label={t("auth.username_label")} htmlFor="auth-username">
            <Input id="auth-username" type="text" value={values.username} onChange={(event) => change("username", event.target.value)} maxLength={64} autoComplete="username" required />
          </Field>
          <Field label={t("auth.password_label")} htmlFor="auth-password">
            <Input id="auth-password" type="password" value={values.password} onChange={(event) => change("password", event.target.value)} autoComplete="current-password" required />
          </Field>
        </FormBody>
      </Card>
    </AccessPage>
  );
}
