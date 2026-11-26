import type { AgentRights, PolicyRefusal, RightState, RightsGroup } from "../api/machines";
import type { Translate } from "../i18n/context";
import { useT } from "../i18n/context";
import { alwaysGranted, capabilityLabelKey } from "../lib/machines";
import { rightsSetLabels, rightsSetPhrases } from "../lib/rights";
import { formatWhen } from "../lib/time";
import { Card, CardBody, CardHeader, Note } from "./Card";
import { TokenBox } from "./Copy";
import { Fold } from "./Disclosure";
import { Pill } from "./Pill";
import { RequestRight } from "./RequestRight";
import { RightPill } from "./RightPill";
import { RootCommand } from "./RootCommand";

// L'onglet Droits d'une machine (A3 R-A3-13) : le jeu posé et sa phrase,
// cinq groupes par ce qu'ils permettent, jamais une liste à plat de noms
// techniques : les noms et leurs échéances restent repliés sous « Voir le
// détail ». Tout vient du serveur : les verdicts (agentpolicy) comme les
// lignes à coller ; rien n'est jugé ni écrit ici. refusal : pourquoi l'agent
// refuse sa politique, quand il le dit (essai E03-08).
export function RightsList({ rights, refusal = null, machineID, machineName, now }: { rights: AgentRights; refusal?: PolicyRefusal | null; machineID: string; machineName: string; now: number }) {
  const t = useT();
  return (
    <>
      <Card>
        <CardHeader title={t("rights.set_title", machineName)} aside={<Pill tone={rights.set === "refused" ? "danger" : "accent"}>{t(rightsSetLabels[rights.set])}</Pill>} />
        <CardBody gap={10}>
          {rights.root_here && <Note tone="danger">{t("rights.root_here", machineName)}</Note>}
          {refusal !== null && <RefusalNote refusal={refusal} />}
          <p>{t(rightsSetPhrases[rights.set])}</p>
          <p className="secondary">{t("rights.how", machineName)}</p>
        </CardBody>
      </Card>
      {rights.groups.map((group) => (
        <GroupCard key={group.name} group={group} machineID={machineID} now={now} />
      ))}
      <Card>
        <CardHeader title={t("rights.other_sets")} />
        <CardBody gap={12}>
          {rights.set_lines.map((setLine) => (
            <div key={setLine.set}>
              <strong>{t(rightsSetLabels[setLine.set])}</strong>
              <RootCommand command={setLine.line} notes={[t("rights.paste_shows_change")]} />
            </div>
          ))}
        </CardBody>
      </Card>
    </>
  );
}

// Une politique refusée : seul observe s'applique, la raison que l'agent
// rapporte avec ce qu'elle nomme (un chemin, une clé : texte de la machine,
// affiché brut), et la commande que le serveur écrit quand elle existe :
// chmod ou chown, pas une commande de l'agent, donc sans RootCommand (ARB-4).
function RefusalNote({ refusal }: { refusal: PolicyRefusal }) {
  const t = useT();
  return (
    <Note tone="danger">
      <p>{t("rights.refusal_title", t(capabilityLabelKey(alwaysGranted)))}</p>
      <p>{t(refusalReasons[refusal.reason], refusal.detail)}</p>
      {refusal.fix_line !== "" && (
        <>
          <p className="secondary">{t("anchor.run_command")}</p>
          <TokenBox value={refusal.fix_line} />
        </>
      )}
    </Note>
  );
}

const refusalReasons: Record<PolicyRefusal["reason"], string> = {
  mode: "rights.refusal_mode",
  owner: "rights.refusal_owner",
  unknown_key: "rights.refusal_unknown_key",
  missing: "rights.refusal_missing",
  unreadable: "rights.refusal_unreadable",
};

// Un groupe : ce qu'il permet, sa coche, ses risques, le geste qui demande
// son droit à la machine et la ligne qui l'ouvre ; replié, ses droits, leurs
// échéances et la ligne qui les retire.
function GroupCard({ group, machineID, now }: { group: RightsGroup; machineID: string; now: number }) {
  const t = useT();
  const verdict = (
    <span className="cluster gap-8">
      {group.worth_root && <Pill tone="danger">{t("rights.worth_root")}</Pill>}
      <RightPill state={group.state} label={verdictLabel(t, group.state, group.until, now)} />
    </span>
  );
  return (
    <Card>
      <CardHeader title={t(`rights.group_${group.name}`)} aside={verdict} />
      <CardBody gap={10}>
        <p className="secondary">{t(`rights.group_${group.name}_hint`)}</p>
        {group.host_terminal && <Note tone="warn">{t("rights.host_terminal_risk")}</Note>}
        {group.request_right !== "" && <RequestRight machineID={machineID} right={group.request_right} />}
        {group.grant_line !== "" && <RootCommand command={group.grant_line} notes={[t("rights.paste_shows_change")]} />}
        <Fold label={t("rights.see_detail")} initiallyOpen={false}>
          {group.worth_root && <p className="secondary">{t("rights.worth_root_why")}</p>}
          <ul className="stack gap-8">
            {group.rights.map((right) => (
              <li key={right.name} className="cluster gap-8">
                <code className="mono">{right.name}</code>
                {right.paths.length > 0 && <span className="mono secondary">{right.paths.join(", ")}</span>}
                <RightPill small state={right.state} label={verdictLabel(t, right.state, right.until, now)} />
              </li>
            ))}
          </ul>
          {group.revoke_line !== "" && (
            <>
              <p className="secondary">{t("rights.revoke_line")}</p>
              <RootCommand command={group.revoke_line} notes={[t("rights.paste_shows_change")]} />
            </>
          )}
        </Fold>
      </CardBody>
    </Card>
  );
}

// La coche d'un groupe ou d'un droit : permis (jusqu'à une heure), pas
// permis ; les deux autres états gardent le libellé de la pastille.
function verdictLabel(t: Translate, state: RightState, until: string | null, now: number): string | undefined {
  if (state === "ok") {
    return until === null ? t("rights.allowed") : t("rights.allowed_until", formatWhen(until, now));
  }
  if (state === "missing") {
    return t("rights.not_allowed");
  }
  return undefined;
}
