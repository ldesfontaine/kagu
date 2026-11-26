import type { JoinGroup, JoinSet, RightsSet } from "../api/machines";
import { useT } from "../i18n/context";
import { rightsSetLabels, rightsSetPhrases } from "../lib/rights";
import { Fold } from "./Disclosure";
import type { IconName } from "./Icon";
import { PickList } from "./PickList";

const setIcons: Record<RightsSet, IconName> = { observe: "eye", manage: "box", root: "shield" };

// Le choix du jeu de droits d'un agent (R-A3-13), à l'ajout d'une machine
// comme à son ré-enrôlement : trois cartes, chacune avec une phrase, ce
// qu'il donne ou ce qu'il coûte. Aucun nom de droit tant que « Voir le
// détail » est fermé ; ouvert, les droits du jeu groupés comme l'onglet
// Droits. Les jeux et leurs droits viennent du serveur.
export function RightsSetChoice({ sets, value, onChange }: { sets: readonly JoinSet[]; value: RightsSet | ""; onChange: (set: RightsSet) => void }) {
  const t = useT();
  const options = sets.map((offered) => ({
    value: offered.set,
    icon: setIcons[offered.set],
    name: t(rightsSetLabels[offered.set]),
    detail: t(rightsSetPhrases[offered.set]),
    more: (
      <Fold label={t("rights.see_detail")} initiallyOpen={false}>
        <SetGroups groups={offered.groups} />
      </Fold>
    ),
  }));
  return <PickList name="rights-set" label={t("machine.set_label")} options={options} value={value} onChange={(chosen) => onChange(chosen as RightsSet)} />;
}

// Les droits d'un jeu, par groupe : le nom du groupe, puis ses droits. Un
// groupe que le jeu n'ouvre pas ne se montre pas.
function SetGroups({ groups }: { groups: readonly JoinGroup[] }) {
  const t = useT();
  return (
    <ul className="stack gap-8">
      {groups.filter((group) => group.rights.length > 0).map((group) => (
        <li key={group.name} className="cluster gap-8">
          <strong>{t(`rights.group_${group.name}`)}</strong>
          {group.rights.map((right) => (
            <code key={right} className="mono">
              {right}
            </code>
          ))}
        </li>
      ))}
    </ul>
  );
}
