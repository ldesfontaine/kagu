import type { RightState } from "../api/machines";
import { useT } from "../i18n/context";
import { rightTones } from "../lib/rights";
import { Pill } from "./Pill";

// Pastille de l'état d'un droit, tel que le serveur le juge : Droit vérifié,
// Droit manquant, Droit pas exerçable, Droits pas encore rapportés. La table
// des tons couvre tout RightState : un état de plus se refuse au typage.
export function RightPill({ state, small = false }: { state: RightState; small?: boolean }) {
  const t = useT();
  return (
    <Pill small={small} tone={rightTones[state]}>
      {t(`backup.right_pill_${state}`)}
    </Pill>
  );
}
