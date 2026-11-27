import { useState } from "react";

import { setup, type AuthState } from "../api/auth";
import { Card, CardBody, CardHeader } from "../components/Card";
import { Failure } from "../components/Failure";
import { Field, Input } from "../components/Field";
import { EnumSelect } from "../components/Select";
import { useAction } from "../hooks/useAction";
import { useT } from "../i18n/context";
import { AccessPage } from "./AccessPage";
import { AccessCredentialsForm } from "./settings/AccessCredentialsForm";
import { AccessForwardForm } from "./settings/AccessForwardForm";
import { AccessTOTPEnrolment } from "./settings/AccessTOTPEnrolment";

// Les deux façons de garder l'interface : la connexion native (un compte et
// son mot de passe), ou le SSO qui transmet l'identité.
const setupModes = ["native", "forward"] as const;

// Tant qu'aucun compte n'existe, le serveur ne sert rien d'autre que la
// création du compte : la porte d'accès (AccessGate) montre cet écran à la
// place de l'interface.
// En connexion native, la réponse pose le cookie de la première session ; en
// mode SSO, la requête est déjà passée par lui. En native, la marche 3
// propose le code à six chiffres (06 §4.2), « Activer » ou « Plus tard » :
// proposé, jamais imposé (R-CNX-2) ; en SSO, elle n'existe pas. Puis
// l'interface s'ouvre : l'agent de cette machine est déjà posé par setup.
export function FirstSetup({ state, onConfigured }: { state: AuthState; onConfigured: () => void }) {
  const t = useT();
  const action = useAction();
  const [mode, setMode] = useState<(typeof setupModes)[number]>("native");
  const [setupCode, setSetupCode] = useState("");
  const [offerTOTP, setOfferTOTP] = useState(false);

  const createAccount = (username: string, password: string) => {
    action.run(() => setup({ setup_code: setupCode, mode: "native", username, password }), { onDone: () => setOfferTOTP(true) });
  };
  const trustProxy = (header: string) => {
    action.run(() => setup({ setup_code: setupCode, mode: "forward", header }), { onDone: onConfigured });
  };

  if (offerTOTP) {
    return (
      <AccessPage>
        <Card className="form-card">
          <CardHeader title={t("auth.totp_title")} />
          <CardBody>
            <AccessTOTPEnrolment onEnabled={onConfigured} onLater={onConfigured} />
          </CardBody>
        </Card>
      </AccessPage>
    );
  }

  return (
    <AccessPage>
        <Card className="form-card">
          <CardHeader title={t("auth.setup_title")} />
          <CardBody>
            <p>{t("auth.setup_intro")}</p>
            <Field label={t("auth.setup_code_label")} htmlFor="auth-setup-code" help={t("auth.setup_code_help")}>
              <Input
                id="auth-setup-code"
                type="text"
                mono
                value={setupCode}
                onChange={(event) => setSetupCode(event.target.value)}
                inputMode="numeric"
                maxLength={8}
                autoComplete="one-time-code"
              />
            </Field>
            <Field label={t("auth.mode_label")} htmlFor="auth-mode">
              <EnumSelect id="auth-mode" value={mode} values={setupModes} labelKey="auth.mode_" onChange={setMode} />
            </Field>
            <Failure error={action.error} />
          </CardBody>
          {mode === "native" && <AccessCredentialsForm minLength={state.password_min_length} busy={action.busy} onSubmit={createAccount} />}
          {mode === "forward" && <AccessForwardForm busy={action.busy} onSubmit={trustProxy} />}
        </Card>
    </AccessPage>
  );
}
