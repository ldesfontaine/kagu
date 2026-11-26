import type { JoinOffer } from "../api/machines";
import { useT } from "../i18n/context";
import { Note } from "./Card";
import { TokenBox } from "./Copy";

// Sans adresse publique en https, aucune machine ne s'ajoute (R-B1-13) :
// l'ajout est grisé et cette note donne la commande, écrite par le serveur,
// qui pose le domaine, sans l'avertissement des lignes de l'agent (ARB-4).
// Rien quand l'ajout est ouvert.
export function JoinNeedsDomain({ join }: { join: JoinOffer | undefined }) {
  const t = useT();
  if (join === undefined || join.ready) {
    return null;
  }
  return (
    <Note tone="warn">
      <p>{t("machine.join_needs_domain_note")}</p>
      <p className="secondary">{t("anchor.run_command")}</p>
      <TokenBox value={join.domain_line} />
    </Note>
  );
}
