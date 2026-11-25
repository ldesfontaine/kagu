import { pingAgent, pinnedKeyState, useMachineActions, useServerKey, type ActionRun } from "../api/actions";
import type { Agent } from "../api/machines";
import { useAction } from "../hooks/useAction";
import { useNow } from "../hooks/useNow";
import { useT, type Translate } from "../i18n/context";
import { stateTones } from "../lib/actions";
import { anchorLabelKey, anchorOfReason } from "../lib/anchors";
import { shownActorName } from "../lib/audit";
import { capabilityLabelKey } from "../lib/machines";
import { reenrollPath } from "../lib/rights";
import { formatWhen } from "../lib/time";
import { AgentGate } from "./AgentGate";
import { TokenBox } from "./Copy";
import { Button } from "./Button";
import { Card, CardBody, CardHeader, Empty, KeyValue, Note } from "./Card";
import { LockedAction } from "./LockedAction";
import { Failure } from "./Failure";
import { Pill } from "./Pill";
import { Table } from "./Table";

// Les ordres d'une machine : la clé du serveur que son agent a épinglée,
// le bouton qui l'éprouve, et les derniers ordres avec leur état. Un ordre
// ne part que vers un agent actif et en ligne : hors ligne, le bouton est
// grisé avec sa raison.
export function ActionsCard({ machineID, agent }: { machineID: string; agent: Agent | null }) {
  const t = useT();
  const now = useNow();
  const runs = useMachineActions(machineID);
  const action = useAction();
  const isActive = agent !== null && agent.revoked_at === null;
  const ping = () => {
    action.run(() => pingAgent(machineID), { topic: "actions" });
  };
  const list = runs.data?.runs ?? [];
  return (
    <Card>
      <CardHeader
        title={t("action.title")}
        aside={
          isActive && (
            <AgentGate machineIDs={[machineID]}>
              {(blocked) => (
                <Button small icon="check" onClick={ping} disabled={action.busy || blocked}>
                  {t("action.ping")}
                </Button>
              )}
            </AgentGate>
          )
        }
      />
      <CardBody gap={10}>
        <p className="secondary">{t("action.subtitle")}</p>
        {agent !== null && <PinnedKey machineID={machineID} agent={agent} />}
        <Failure error={action.error} />
        {runs.error && <Failure error={runs.error} />}
      </CardBody>
      {runs.data && list.length === 0 && <Empty text={t("action.empty")} />}
      {list.length > 0 && (
        <Table>
          <thead>
            <tr>
              <th>{t("action.col_when")}</th>
              <th>{t("action.col_kind")}</th>
              <th>{t("action.col_state")}</th>
              <th className="wide-only">{t("action.col_by")}</th>
            </tr>
          </thead>
          <tbody>
            {list.map((run) => (
              <RunRow key={run.id} run={run} now={now} />
            ))}
          </tbody>
        </Table>
      )}
      <CardBody>
        <p className="secondary">{t("action.note")}</p>
      </CardBody>
    </Card>
  );
}

// La clé que l'agent dit accepter, comparée à celle de ce serveur : une autre
// clé, ou aucune, fera refuser chaque ordre. La précédente, pendant une
// rotation, est encore bonne. Aucun ordre ne livre la neuve : l'écran donne
// la ligne « trust set » que le serveur rend, et renvoie l'empreinte à
// comparer à la machine du serveur, jamais à l'écran (R-A3-15).
function PinnedKey({ machineID, agent }: { machineID: string; agent: Agent }) {
  const t = useT();
  const serverKey = useServerKey();
  if (agent.server_key_fingerprint === "") {
    return (
      <>
        <KeyValue label={t("action.server_key")} value={t("action.server_key_none")} />
        {serverKey.data && <TokenBox value={serverKey.data.trust_line} />}
        <ReenrollButton machineID={machineID} />
      </>
    );
  }
  const pinned = pinnedKeyState(serverKey.data, agent.server_key_fingerprint);
  return (
    <>
      <KeyValue label={t("action.server_key")} value={agent.server_key_fingerprint} mono />
      {pinned === "previous" && serverKey.data && (
        <Note tone="warn">
          <p>{t("action.server_key_previous")}</p>
          <TokenBox value={serverKey.data.trust_line} />
        </Note>
      )}
      {pinned === "differs" && serverKey.data && (
        <Note tone="danger">
          <p>{t("action.server_key_differs")}</p>
          <TokenBox value={serverKey.data.trust_line} />
        </Note>
      )}
    </>
  );
}

// Ce qui se corrige par un ré-enrôlement sans droit à cocher (la clé du serveur).
function ReenrollButton({ machineID }: { machineID: string }) {
  const t = useT();
  return (
    <div>
      <Button small icon="refresh" to={reenrollPath(machineID)}>
        {t("machine.reenroll")}
      </Button>
    </div>
  );
}

function RunRow({ run, now }: { run: ActionRun; now: number }) {
  const t = useT();
  const output = run.output.map((line) => line.line).join("\n");
  return (
    <tr>
      <td>{formatWhen(run.requested_at, now)}</td>
      <td>{t(`action.kind_${run.kind.split(".").join("_")}`)}</td>
      <td>
        <Pill tone={stateTones[run.state]}>{t(`action.state_${run.state}`)}</Pill>
        {run.reason !== "" && <div className="secondary">{reasonText(t, run.reason)}</div>}
        {run.fix !== undefined && <LockedAction fix={run.fix} />}
        {run.reason === "server_key_missing" && run.machine_id !== null && <ReenrollButton machineID={run.machine_id} />}
        {output !== "" && <pre className="secondary">{output}</pre>}
      </td>
      <td className="wide-only">{shownActorName(run.requested_by, run.requested_by_label)}</td>
    </tr>
  );
}

// La raison d'un refus ; right_missing porte après « : » le droit qui manque.
export function reasonText(t: Translate, reason: string): string {
  // Une ancre de confiance locale a fait refuser l'ordre : la phrase nomme le type.
  const anchored = anchorOfReason(reason);
  if (anchored !== null) {
    return t(`action.reason_anchor_${anchored.why}`, t(anchorLabelKey(anchored.name)));
  }
  const [code, right] = reason.split(":");
  if (right !== undefined) {
    return t(`action.reason_${code}`, t(capabilityLabelKey(right)));
  }
  return t(`action.reason_${code}`);
}
