import { useState } from "react";
import { useNavigate } from "react-router";

import { reenrollMachine, type JoinOffer, type Machine, type RightsSet, type TokenResponse } from "../../api/machines";
import { Button } from "../../components/Button";
import { Failure } from "../../components/Failure";
import { JoinNeedsDomain } from "../../components/JoinNeedsDomain";
import { Modal, ModalCancel } from "../../components/Modal";
import { RightsSetChoice } from "../../components/RightsSetChoice";
import { WizardBar } from "../../components/Wizard";
import { useAction } from "../../hooks/useAction";
import { useT } from "../../i18n/context";
import { EnrollFlow } from "./EnrollFlow";
import { RoutedMachine } from "./RoutedMachine";

// « Ré-enrôler » : la fenêtre de la fiche d'une machine, à l'adresse
// /machines/:id/reenroller : un nouvel agent, avec une nouvelle clé, remplace
// l'ancien. 1. le jeu de droits, celui de l'agent courant d'avance ; 2. les
// lignes à coller ; 3. l'attente du nouvel agent (EnrollFlow). Un droit qui
// manque ne mène pas ici : il se pose en root sur la machine (agent grant).
export function ReenrollMachine() {
  return <RoutedMachine>{(machine, machines) => <ReenrollDialog machine={machine} join={machines.join} />}</RoutedMachine>;
}

function ReenrollDialog({ machine, join }: { machine: Machine; join: JoinOffer }) {
  const t = useT();
  const navigate = useNavigate();
  const held = heldSet(machine, join);
  const [chosen, setChosen] = useState<RightsSet | "">(held);
  const action = useAction();
  const [token, setToken] = useState<TokenResponse | null>(null);
  // L'agent d'avant, retenu à la création du jeton : celui qui arrive en diffère.
  const [previousAgentID, setPreviousAgentID] = useState<string | null>(null);
  const close = () => void navigate(`/machines/${machine.id}`, { replace: true });
  const titles = [t("machine.step_rights"), t("machine.step_install"), t("machine.step_wait")];
  const title = t("machine.reenroll_title", machine.name);

  if (token !== null) {
    return <EnrollFlow title={title} titles={titles} token={token} target={{ kind: "reenroll", machineID: machine.id, previousAgentID }} onClose={close} />;
  }

  const create = () => {
    if (chosen === "") {
      return;
    }
    action.run(() => reenrollMachine(machine.id, chosen), {
      topic: "all",
      onDone: (created) => {
        setPreviousAgentID(machine.agent?.id ?? null);
        setToken(created);
      },
    });
  };

  return (
    <Modal
      title={title}
      onClose={close}
      dirty={chosen !== held}
      wide
      actions={
        <>
          <ModalCancel />
          <Button variant="primary" icon="refresh" disabled={action.busy || !join.ready || chosen === ""} onClick={create}>
            {t("machine.rights_submit")}
          </Button>
        </>
      }
    >
      <WizardBar titles={titles} position={0} reached={0} canJump={false} onJump={() => undefined} />
      <p className="secondary">{t("machine.rights_subtitle")}</p>
      <JoinNeedsDomain join={join} />
      <RightsSetChoice sets={join.sets} value={chosen} onChange={setChosen} />
      <Failure error={action.error} />
    </Modal>
  );
}

// Le jeu que tient l'agent courant, tel que le serveur l'a jugé, s'il est
// l'un des trois offerts ; sinon rien n'est choisi d'avance.
function heldSet(machine: Machine, join: JoinOffer): RightsSet | "" {
  const set = machine.agent?.rights?.set ?? "";
  return join.sets.find((offered) => offered.set === set)?.set ?? "";
}
