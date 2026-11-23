import { useState } from "react";

import { changePassword, disableTOTP, useOpenSessions, type AuthState, type PasswordChange } from "../../api/auth";
import { Button } from "../../components/Button";
import { Note } from "../../components/Card";
import { Failure } from "../../components/Failure";
import { Input } from "../../components/Field";
import { Pill } from "../../components/Pill";
import { SettingBlock, SettingFoot, SettingRow } from "../../components/SettingRow";
import { useAction } from "../../hooks/useAction";
import { useNow } from "../../hooks/useNow";
import { useT } from "../../i18n/context";
import { isForwardInsecure } from "../../lib/auth";
import { ago } from "../../lib/time";
import { AccessPasswordForm } from "./AccessPasswordForm";
import { AccessSessionsBlock } from "./AccessSessionsBlock";
import { AccessTOTPEnrolment } from "./AccessTOTPEnrolment";
import { SettingsSection } from "./SettingsSection";

function reloadPage() {
  window.location.reload();
}

// L'accès à l'interface, tel que la première configuration l'a posé. En
// connexion native : l'identifiant, les sessions ouvertes, le code à six
// chiffres (proposé, jamais imposé), le changement de mot de passe. Changer le mot de passe ferme les autres sessions et garde
// la courante : l'écran le dit, avec les jetons d'API qui vivent encore.
// Refaire un accès perdu ou changer de mode ne se fait pas ici : root le fait
// sur la machine, par le canal local (R-A2-10), et la section le dit. En mode
// SSO, il n'y a rien à saisir après coup : la section montre l'en-tête,
// l'identité que le SSO transmet, et qui peut entrer.
export function AccessSection({ state, reload }: { state: AuthState; reload: () => void }) {
  const t = useT();
  const now = useNow();
  const action = useAction();
  const enabled = state.mode !== "none";
  const native = state.mode === "native";
  const sessions = useOpenSessions(native);
  const [changed, setChanged] = useState<PasswordChange | null>(null);

  const changeTo = (current: string, password: string) => {
    action.run(() => changePassword(current, password), {
      onDone: (change) => {
        setChanged(change);
        sessions.reload();
      },
    });
  };

  return (
    <SettingsSection
      id="acces"
      titleKey="settings.section_access"
      text={t("auth.intro")}
      aside={<Pill tone={enabled && !isForwardInsecure(state) ? "ok" : "warn"}>{t(`auth.state_${state.mode}`)}</Pill>}
    >
      {isForwardInsecure(state) && (
        <SettingBlock>
          <Note tone="warn">{t("auth.forward_insecure")}</Note>
        </SettingBlock>
      )}
      {native && (
        <>
          <SettingRow label={t("auth.username_label")}>
            <span className="mono">{state.username}</span>
          </SettingRow>
          <AccessSessionsBlock sessions={sessions} onSignedOut={reloadPage} />
          <AccessTOTPRows active={state.totp === true} onChanged={reload} />
        </>
      )}
      {state.mode === "forward" && (
        <>
          <SettingBlock>
            <p>{t("auth.forward_text", state.header ?? "", state.username)}</p>
          </SettingBlock>
          <SettingRow label={t("auth.header_label")}>
            <span className="mono">{state.header ?? ""}</span>
          </SettingRow>
          <SettingRow label={t("auth.identity_label")}>
            <span className="mono">{state.username}</span>
          </SettingRow>
          <SettingRow label={t("auth.who_label")} block>
            {state.allowed_users === null ? (
              <Note tone="warn">{t("auth.who_everyone")}</Note>
            ) : (
              <Note tone="ok">{t("auth.who_listed", state.allowed_users.join(", "))}</Note>
            )}
          </SettingRow>
        </>
      )}
      {changed !== null ? (
        <SettingBlock>
          <Note tone="ok">{t("auth.password_changed")}</Note>
          {changed.api_tokens > 0 && <Note tone="warn">{t("auth.tokens_remain", changed.api_tokens)}</Note>}
          <Button variant="primary" icon="check" onClick={() => setChanged(null)}>
            {t("auth.tokens_continue")}
          </Button>
        </SettingBlock>
      ) : (
        native && <AccessPasswordForm minLength={state.password_min_length} busy={action.busy} onSubmit={changeTo} />
      )}
      {action.error !== null && (
        <SettingBlock>
          <Failure error={action.error} />
        </SettingBlock>
      )}
      {enabled && (
        <SettingRow label={t("auth.title")} description={state.enabled_at === null ? undefined : t("auth.enabled_since", ago(t, state.enabled_at, now))} block>
          <Note tone="neutral">{t("auth.rescue_local")}</Note>
        </SettingRow>
      )}
    </SettingsSection>
  );
}

// Le code à six chiffres de la connexion : le poser (le carré, puis un premier
// code), ou le retirer, sur le mot de passe. Un téléphone perdu se règle par
// root, sur la machine : la ligne le dit.
function AccessTOTPRows({ active, onChanged }: { active: boolean; onChanged: () => void }) {
  const t = useT();
  const action = useAction();
  const [enrolling, setEnrolling] = useState(false);
  const [password, setPassword] = useState("");

  if (!active) {
    return (
      <SettingRow label={t("auth.totp_title")} description={t("auth.totp_intro")} block>
        {enrolling ? (
          <AccessTOTPEnrolment
            onEnabled={() => {
              setEnrolling(false);
              onChanged();
            }}
          />
        ) : (
          <Button icon="shield" onClick={() => setEnrolling(true)}>
            {t("auth.totp_enable")}
          </Button>
        )}
      </SettingRow>
    );
  }
  const remove = () => {
    action.run(() => disableTOTP(password), { onDone: onChanged });
  };
  return (
    <form
      className="setting-stack"
      onSubmit={(event) => {
        event.preventDefault();
        remove();
      }}
    >
      <SettingRow label={t("auth.totp_title")} description={t("auth.totp_rescue")}>
        <Pill tone="ok">{t("auth.totp_on")}</Pill>
      </SettingRow>
      <SettingRow label={t("auth.password_label")} htmlFor="totp-password" width="medium">
        <Input id="totp-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required />
      </SettingRow>
      {action.error !== null && (
        <SettingBlock>
          <Failure error={action.error} />
        </SettingBlock>
      )}
      <SettingFoot note={t("auth.totp_disable_note")}>
        <Button type="submit" icon="x" disabled={action.busy}>
          {t("auth.totp_disable")}
        </Button>
      </SettingFoot>
    </form>
  );
}
