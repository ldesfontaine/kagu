import { Link } from "react-router";

import { useT } from "../i18n/context";
import { TokenBox } from "./Copy";

// La ligne à lancer en root sur la machine, telle que le serveur l'a écrite :
// celle d'une ancre de confiance locale (trust) ou celle qui pose un droit
// (grant). L'unique endroit qui la montre ; rien n'y est ajouté ici.
// notes : ce qui se lit sous la ligne. link : où voir ce que l'agent tient.
// short : dans une carte ou une ligne étroite, la ligne seule, tronquée,
// entière dans l'infobulle.
export function RootCommand({ command, notes = [], link, short = false }: { command: string; notes?: readonly string[]; link?: { to: string; label: string } | undefined; short?: boolean }) {
  const t = useT();
  if (short) {
    return <TokenBox value={command} title={[t("anchor.run_command"), command, ...notes].join(" ")} short />;
  }
  return (
    <div className="root-command">
      <p className="secondary">{t("anchor.run_command")}</p>
      <TokenBox value={command} />
      {notes.map((note) => (
        <p key={note} className="secondary">
          {note}
        </p>
      ))}
      {link !== undefined && <Link to={link.to}>{link.label}</Link>}
    </div>
  );
}
