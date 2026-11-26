import type { RefusalFix } from "../api/client";
import { usePendingLine, useT } from "../i18n/context";
import { machineAgentPath } from "../lib/rights";
import { RequestRight } from "./RequestRight";
import { RootCommand } from "./RootCommand";

// Ce qui rouvre un geste fermé, tel que le serveur le joint au refus (fix) :
// pour un droit, la ligne constante « grant --pending » à lancer en root sur
// la machine dont l'agent doit le tenir, le droit dit à côté (R-DROIT-8) ;
// pour une ancre, la commande trust. Rien n'est écrit ici : la ligne vient du
// refus, sinon de la session (un écran qui sait le droit d'un geste fermé
// construit son fix lui-même).
// path : le chemin que le droit devra couvrir, que seul l'écran connaît ; il
// se dit à côté de la ligne, jamais dedans.
// short : dans une carte ou une ligne étroite, la ligne seule, tronquée.
export function LockedAction({ fix, path, short = false }: { fix: RefusalFix; path?: string | undefined; short?: boolean }) {
  const t = useT();
  if (fix.right !== undefined && fix.machine !== undefined) {
    return <PendingLine machineID={fix.machine} right={fix.right} command={fix.command} path={path} short={short} />;
  }
  if (fix.command !== undefined) {
    // exact : la commande pose la valeur de l'ordre ; sinon c'est « trust
    // list », et la fiche dit ce que l'agent tient.
    const link = fix.exact !== true && fix.machine !== undefined && fix.machine !== "" ? { to: machineAgentPath(fix.machine), label: t("anchor.see_machine") } : undefined;
    return <RootCommand command={fix.command} link={link} />;
  }
  return null;
}

// La ligne d'un droit manquant : celle du refus, sinon celle de la session ;
// rien si le serveur n'en donne pas. Le droit et le chemin se disent à côté,
// jamais dans la ligne, avec l'avertissement : un serveur pris sert aussi
// l'écran. À côté, hors d'une ligne étroite, le geste qui demande le droit à
// la machine (ARB-1) : sans lui, la ligne constante ne trouverait rien.
function PendingLine({ machineID, right, command, path, short }: { machineID: string; right: string; command: string | undefined; path: string | undefined; short: boolean }) {
  const t = useT();
  const sessionLine = usePendingLine();
  const line = command !== undefined && command !== "" ? command : sessionLine;
  if (line === "") {
    return null;
  }
  const where = path !== undefined && path !== "" ? [t("machine.grant_path", path)] : [];
  const notes = [t("rights.missing_right", right), ...where, t("rights.paste_shows_change")];
  if (short || machineID === "") {
    return <RootCommand command={line} notes={notes} short={short} />;
  }
  return (
    <>
      <RequestRight machineID={machineID} right={right} />
      <RootCommand command={line} notes={notes} />
    </>
  );
}
