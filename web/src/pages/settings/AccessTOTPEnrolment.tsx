import { useEffect, useState } from "react";

import { enableTOTP, proposeTOTP, type TOTPProposal } from "../../api/auth";
import { failureOf, type ApiError } from "../../api/client";
import { Button } from "../../components/Button";
import { TokenBox } from "../../components/Copy";
import { Failure } from "../../components/Failure";
import { Field, Input } from "../../components/Field";
import { useAction } from "../../hooks/useAction";
import { useT } from "../../i18n/context";

// Poser le code à six chiffres : le carré à scanner et sa clé copiable, puis
// un premier code de l'application, que le serveur juge avant de garder le
// secret. Le secret est tiré une fois, à l'ouverture : une relecture en
// tirerait un autre, et le carré déjà scanné ne vaudrait plus. Sert à la
// première configuration (marche 3, avec « Plus tard ») et aux réglages.
export function AccessTOTPEnrolment({ onEnabled, onLater }: { onEnabled: () => void; onLater?: () => void }) {
  const t = useT();
  const action = useAction();
  const [proposal, setProposal] = useState<TOTPProposal | null>(null);
  const [loadError, setLoadError] = useState<ApiError | null>(null);
  const [code, setCode] = useState("");

  useEffect(() => {
    proposeTOTP().then(setProposal, (failure: unknown) => setLoadError(failureOf(failure)));
  }, []);

  const enable = () => {
    if (proposal !== null) {
      action.run(() => enableTOTP(proposal.secret, code), { onDone: onEnabled });
    }
  };

  return (
    <form
      className="stack gap-14"
      onSubmit={(event) => {
        event.preventDefault();
        enable();
      }}
    >
      <p>{t("auth.totp_intro")}</p>
      <p className="secondary">{t("auth.totp_scan")}</p>
      {proposal !== null && (
        <>
          <img src={proposal.qr_code} alt={t("auth.totp_qr_alt")} width={200} height={200} />
          <Field label={t("auth.totp_key_label")}>
            <TokenBox value={proposal.secret} />
          </Field>
        </>
      )}
      <Field label={t("auth.totp_code_label")} htmlFor="totp-code">
        <Input id="totp-code" type="text" mono value={code} onChange={(event) => setCode(event.target.value)} inputMode="numeric" maxLength={6} autoComplete="one-time-code" required />
      </Field>
      <Failure error={loadError ?? action.error} />
      <div className="cluster">
        <Button type="submit" variant="primary" icon="shield" disabled={proposal === null || action.busy}>
          {t("auth.totp_enable")}
        </Button>
        {onLater !== undefined && <Button onClick={onLater}>{t("auth.totp_later")}</Button>}
      </div>
    </form>
  );
}
