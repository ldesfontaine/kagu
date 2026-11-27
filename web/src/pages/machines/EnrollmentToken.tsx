import type { TokenResponse } from "../../api/machines";
import { KeyValue, Note } from "../../components/Card";
import { TokenBox } from "../../components/Copy";
import { useT } from "../../i18n/context";
import { joinPasteText } from "../../lib/machines";
import { formatRemaining } from "../../lib/time";

// Les deux lignes à coller sur la machine (B1 §3) : la commande join, écrite
// par le serveur, puis le jeton, montré à part. Un seul « Copier » prend les
// deux. Le jeton ne s'affiche qu'une fois : l'appelant tient la réponse en
// mémoire, jamais dans l'adresse ni dans l'historique du navigateur. Pour un
// ré-enrôlement, les deux commandes qui retirent l'agent en place passent
// avant, une par ligne. Aucune n'est une commande de l'agent : pas de
// RootCommand ni de son avertissement (ARB-4) ; la ligne d'ajout porte sa note.
export function EnrollmentToken({ token }: { token: TokenResponse }) {
  const t = useT();
  const expiresIn = formatRemaining(t, Date.parse(token.expires_at) - Date.now());
  return (
    <>
      <p className="secondary">{t("machine.token_subtitle", token.name)}</p>
      <Note tone="warn">{t("machine.token_once", expiresIn)}</Note>
      {token.reenroll_lines.length > 0 && (
        <>
          <p className="secondary">{t("machine.join_reenroll_first")}</p>
          <TokenBox value={token.reenroll_lines.join("\n")} lines />
        </>
      )}
      <p>{t("machine.join_paste")}</p>
      <TokenBox value={token.command} copy={joinPasteText(token)} />
      <p className="secondary">{t("machine.join_line_check")}</p>
      <KeyValue label={t("machine.join_token")} value={token.token} mono />
      <p className="secondary">{t("machine.join_confirm")}</p>
    </>
  );
}
