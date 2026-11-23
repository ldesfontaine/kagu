import { Button } from "../../components/Button";
import { Failure } from "../../components/Failure";
import { Input } from "../../components/Field";
import { SettingBlock, SettingFoot, SettingRow } from "../../components/SettingRow";
import { usePasswordForm } from "../../hooks/usePasswordForm";
import { useT } from "../../i18n/context";

// Changer le mot de passe : deux lignes et le bouton principal de la section.
// Il se joue contre la règle du serveur avant l'envoi, pour dire le refus sans
// attendre. Il vit dans la carte de l'accès, avec ses lignes.
export function AccessPasswordForm({ minLength, busy, onSubmit }: { minLength: number; busy: boolean; onSubmit: (password: string) => void }) {
  const t = useT();
  const { values, change, error, submit } = usePasswordForm(minLength, (valid) => onSubmit(valid.password));
  return (
    <form
      className="setting-stack"
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <div className="setting-subhead">
        <span className="card-t">{t("auth.change_title")}</span>
      </div>
      <SettingRow label={t("auth.password_label")} description={t("auth.password_help", minLength)} htmlFor="auth-password" width="medium">
        <Input id="auth-password" type="password" value={values.password} onChange={(event) => change("password", event.target.value)} autoComplete="new-password" required />
      </SettingRow>
      <SettingRow label={t("auth.confirm_label")} htmlFor="auth-confirm" width="medium">
        <Input id="auth-confirm" type="password" value={values.confirmation} onChange={(event) => change("confirmation", event.target.value)} autoComplete="new-password" required />
      </SettingRow>
      {error !== null && (
        <SettingBlock>
          <Failure error={error} />
        </SettingBlock>
      )}
      <SettingFoot note={t("auth.browser_prompt")}>
        <Button type="submit" variant="primary" icon="check" disabled={busy}>
          {t("auth.change")}
        </Button>
      </SettingFoot>
    </form>
  );
}
