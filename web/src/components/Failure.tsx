import { errorKey, type ApiError } from "../api/client";
import { useT } from "../i18n/context";
import { refusalArguments } from "../lib/auth";
import { fixOfRefusal } from "../lib/rights";
import { Note } from "./Card";
import { LockedAction } from "./LockedAction";

// Ce que seul l'écran sait d'un refus : la machine dont il parle (pour une
// ancre, le lien vers sa fiche) et le chemin qu'un droit borné devra couvrir.
export interface RightGesture {
  machineID?: string;
  path?: string;
}

// Une erreur se dit en note, jamais en pastille : la pastille dit l'état
// d'un objet. L'erreur arrive telle que l'API l'a rendue, ou déjà en clé du
// catalogue (les formulaires). Sans erreur, rien. Un refus qui porte de quoi
// le lever (fix : un droit et sa machine, ou la commande d'une ancre) porte
// son geste : la cause est corrigée ici, pas dans chaque écran.
export function Failure({ error, gesture }: { error: ApiError | string | null | undefined; gesture?: RightGesture | undefined }) {
  const t = useT();
  if (error === null || error === undefined) {
    return null;
  }
  const key = typeof error === "string" ? error : errorKey(error);
  const args = typeof error === "string" ? [] : refusalArguments(error, Date.now());
  const fix = fixOfRefusal(error);
  if (fix === null) {
    return <Note tone="danger">{t(key, ...args)}</Note>;
  }
  const machine = fix.machine ?? gesture?.machineID;
  return (
    <Note tone="danger">
      <p>{t(key, ...args)}</p>
      <LockedAction fix={machine === undefined ? fix : { ...fix, machine }} path={gesture?.path} />
    </Note>
  );
}
