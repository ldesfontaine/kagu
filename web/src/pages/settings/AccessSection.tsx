import { useState } from "react";

import { changePassword, disableAuth, useOpenSessions, type AuthState, type PasswordChange } from "../../api/auth";
import { Button } from "../../components/Button";
import { Note } from "../../components/Card";
import { ConfirmInline } from "../../components/ConfirmInline";
import { Failure } from "../../components/Failure";
import { Pill } from "../../components/Pill";
import { DangerZone, SettingBlock, SettingRow } from "../../components/SettingRow";
import { useAction } from "../../hooks/useAction";
import { useNow } from "../../hooks/useNow";
import { useT } from "../../i18n/context";
import { isForwardInsecure } from "../../lib/auth";
import { ago } from "../../lib/time";
import { AccessPasswordForm } from "./AccessPasswordForm";
import { AccessSessionsBlock } from "./AccessSessionsBlock";
import { SettingsSection } from "./SettingsSection";

function reloadPage() {
  window.location.reload();
}

// L'accès à l'interface, tel que la première configuration l'a posé. En
// connexion native : l'identifiant, les sessions ouvertes, le changement de
// mot de passe. Changer le mot de passe ferme les autres sessions et garde
// la courante : l'écran le dit, avec les jetons d'API qui vivent encore.
// Désactiver ramène l'installation à sa première configuration : il est dans
// la zone de danger, derrière une confirmation en ligne. En mode SSO, il n'y
// a rien à saisir après coup : la section montre l'en-tête, l'identité que le
// SSO transmet, et qui peut entrer.
export function AccessSection({ state }: { state: AuthState }) {
  const t = useT();
  const now = useNow();
  const action = useAction();
  const enabled = state.mode !== "none";
  const native = state.mode === "native";
  const sessions = useOpenSessions(native);
  const [changed, setChanged] = useState<PasswordChange | null>(null);

  const disable = () => {
    action.run(() => disableAuth(), { onDone: reloadPage });
  };
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
        <DangerZone>
          <SettingRow label={t("auth.title")} description={state.enabled_at === null ? undefined : t("auth.enabled_since", ago(t, state.enabled_at, now))}>
            <ConfirmInline variant="danger" icon="x" disabled={action.busy} question={t("auth.disable_confirm")} onConfirm={disable}>
              {t("auth.disable")}
            </ConfirmInline>
          </SettingRow>
        </DangerZone>
      )}
    </SettingsSection>
  );
}
