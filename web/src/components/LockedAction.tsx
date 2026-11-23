import type { RefusalFix } from "../api/client";
import { useT } from "../i18n/context";
import { capabilityLabelKey } from "../lib/machines";
import { reenrollPath } from "../lib/rights";
import { AnchorFix } from "./AnchorFix";
import { Button } from "./Button";

// Ce qui rouvre un geste fermé, tel que le serveur le joint au refus (fix) :
// pour un droit, « Ré-enrôler avec ce droit », sur la machine dont l'agent
// doit le tenir (la ligne grant le remplacera, T03-03) ; pour une ancre, la
// commande à lancer en root sur la machine. Rien n'est recalculé ici.
// path : le chemin que le droit devra couvrir, que seul l'écran connaît.
// short : dans une carte ou une ligne étroite, le droit en entier dans
// l'infobulle et pour les lecteurs d'écran.
export function LockedAction({ fix, path, short = false }: { fix: RefusalFix; path?: string | undefined; short?: boolean }) {
  const t = useT();
  if (fix.right !== undefined && fix.machine !== undefined) {
    const full = t("machine.reenroll_with", t(capabilityLabelKey(fix.right)));
    return (
      <Button small icon="refresh" to={reenrollPath(fix.machine, { name: fix.right, path })} {...(short ? { title: full, "aria-label": full } : {})}>
        {short ? t("machine.reenroll_with_right") : full}
      </Button>
    );
  }
  if (fix.command !== undefined) {
    return <AnchorFix command={fix.command} exact={fix.exact === true} machineID={fix.machine} />;
  }
  return null;
}
