import type { RefusalFix } from "../api/client";
import { useGrantLine, useT } from "../i18n/context";
import { machineAgentPath } from "../lib/rights";
import { RootCommand } from "./RootCommand";

// Ce qui rouvre un geste fermé, tel que le serveur le joint au refus (fix) :
// pour un droit, la ligne grant à lancer en root sur la machine dont l'agent
// doit le tenir ; pour une ancre, la commande trust. Rien n'est écrit ici :
// la ligne vient du refus, sinon de la session (un écran qui sait le droit
// d'un geste fermé construit son fix lui-même).
// path : le chemin que le droit devra couvrir, que seul l'écran connaît ; il
// se dit à côté de la ligne, jamais dedans.
// short : dans une carte ou une ligne étroite, la ligne seule, tronquée.
export function LockedAction({ fix, path, short = false }: { fix: RefusalFix; path?: string | undefined; short?: boolean }) {
  const t = useT();
  if (fix.right !== undefined && fix.machine !== undefined) {
    return <GrantLine right={fix.right} command={fix.command} path={path} short={short} />;
  }
  if (fix.command !== undefined) {
    // exact : la commande pose la valeur de l'ordre ; sinon c'est « trust
    // list », et la fiche dit ce que l'agent tient.
    const link = fix.exact !== true && fix.machine !== undefined && fix.machine !== "" ? { to: machineAgentPath(fix.machine), label: t("anchor.see_machine") } : undefined;
    return <RootCommand command={fix.command} link={link} />;
  }
  return null;
}

// La ligne grant d'un droit : celle du refus, sinon celle de la session ;
// rien si le serveur n'en donne pas (ligne refusée).
function GrantLine({ right, command, path, short }: { right: string; command: string | undefined; path: string | undefined; short: boolean }) {
  const t = useT();
  const sessionLine = useGrantLine(right);
  const line = command !== undefined && command !== "" ? command : sessionLine;
  if (line === "") {
    return null;
  }
  const notes = path !== undefined && path !== "" ? [t("machine.grant_path", path), t("rights.paste_shows_change")] : [t("rights.paste_shows_change")];
  return <RootCommand command={line} notes={notes} short={short} />;
}
