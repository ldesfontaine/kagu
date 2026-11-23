import { useState } from "react";

import { setup, type AuthState } from "../api/auth";
import { offerLocalEnrollment, type TokenResponse } from "../api/machines";
import { Button } from "../components/Button";
import { Card, CardBody, CardHeader, Note } from "../components/Card";
import { Failure } from "../components/Failure";
import { Field, Input } from "../components/Field";
import { InstallSteps } from "../components/InstallSteps";
import { PublicUrlNote } from "../components/PublicUrlNote";
import { EnumSelect } from "../components/Select";
import { useAction } from "../hooks/useAction";
import { useChecklist } from "../hooks/useChecklist";
import { useT } from "../i18n/context";
import { formatRemaining } from "../lib/time";
import { AccessPage } from "./AccessPage";
import { AccessCredentialsForm } from "./settings/AccessCredentialsForm";
import { AccessForwardForm } from "./settings/AccessForwardForm";

// Les deux façons de garder l'interface : la connexion native (un compte et
// son mot de passe), ou le SSO qui transmet l'identité.
const setupModes = ["native", "forward"] as const;

// Tant qu'aucun compte n'existe, le serveur ne sert rien d'autre que la
// création du compte : la porte d'accès (AccessGate) montre cet écran à la
// place de l'interface.
// En connexion native, la réponse pose le cookie de la première session ; en
// mode SSO, la requête est déjà passée par lui. Puis la première étape de
// l'installation : la ligne qui installe l'agent de cette machine, tant
// qu'elle n'en a jamais eu ; sinon l'interface s'ouvre.
export function FirstSetup({ state, onConfigured }: { state: AuthState; onConfigured: () => void }) {
  const t = useT();
  const action = useAction();
  const [mode, setMode] = useState<(typeof setupModes)[number]>("native");
  const [agentLine, setAgentLine] = useState<TokenResponse | null>(null);
  const [setupCode, setSetupCode] = useState("");

  const showAgentLineOrOpen = (line: TokenResponse | null) => {
    if (line === null) {
      onConfigured();
      return;
    }
    setAgentLine(line);
  };
  const createAccount = (username: string, password: string) => {
    action.run(
      async () => {
        await setup({ setup_code: setupCode, mode: "native", username, password });
        return agentLineOrNull();
      },
      { onDone: showAgentLineOrOpen },
    );
  };
  const trustProxy = (header: string) => {
    action.run(
      async () => {
        await setup({ setup_code: setupCode, mode: "forward", header });
        return agentLineOrNull();
      },
      { onDone: showAgentLineOrOpen },
    );
  };

  if (agentLine !== null) {
    return <AgentLine line={agentLine} onContinue={onConfigured} />;
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

// La ligne de l'agent de cette machine, ou rien : elle a déjà eu un agent
// (409), ou la ligne ne s'obtient pas. Le compte est créé quoi qu'il arrive,
// l'interface doit pouvoir s'ouvrir ; la fiche de la machine redonne la
// ligne (Ré-enrôler).
async function agentLineOrNull(): Promise<TokenResponse | null> {
  try {
    return await offerLocalEnrollment();
  } catch {
    return null;
  }
}

// La deuxième étape : les étapes qui installent l'agent de la machine où tourne
// le serveur, à coller sur elle. Elles ne s'affichent qu'ici, une fois.
function AgentLine({ line, onContinue }: { line: TokenResponse; onContinue: () => void }) {
  const t = useT();
  const installed = useChecklist();
  const expiresIn = formatRemaining(t, Date.parse(line.expires_at) - Date.now());
  return (
    <AccessPage>
        <Card className="form-card">
          <CardHeader title={t("auth.setup_agent_title")} />
          <CardBody>
            <p>{t("auth.setup_agent_intro")}</p>
            <Note tone="warn">{t("machine.token_once", expiresIn)}</Note>
            <p className="secondary">{t("machine.install_root_note")}</p>
            <InstallSteps steps={line.steps} produces={false} done={installed.done} onToggle={installed.toggle} />
            <PublicUrlNote local={line.url_local} suggestion={line.url_suggestion} />
            <p className="secondary">{t("auth.setup_agent_later")}</p>
            <div className="cluster">
              <Button onClick={onContinue}>{t("auth.setup_continue")}</Button>
            </div>
          </CardBody>
        </Card>
    </AccessPage>
  );
}
