import { useId, useState, type FormEvent } from "react";
import { useNavigate } from "react-router";

import { createMachineToken, useMachines, type RoleID, type TokenResponse } from "../../api/machines";
import { Button } from "../../components/Button";
import { Failure } from "../../components/Failure";
import { Field, Input } from "../../components/Field";
import { JoinNeedsDomain } from "../../components/JoinNeedsDomain";
import { Select } from "../../components/Select";
import { Modal, ModalCancel } from "../../components/Modal";
import { RightsSetChoice } from "../../components/RightsSetChoice";
import { WizardBar } from "../../components/Wizard";
import { useAction } from "../../hooks/useAction";
import { useForm } from "../../hooks/useForm";
import { useRoles, useT } from "../../i18n/context";
import { emptyMachineForm, isMachineFormModified } from "../../lib/machines";
import { EnrollFlow } from "./EnrollFlow";

// « Ajouter une machine » : une fenêtre à trois étapes sur la liste des
// machines, à l'adresse /machines/nouvelle (la liste est le fond, comme au
// rechargement). 1. nommer la machine, choisir son rôle (ses modules) et le
// jeu de droits de son agent ; 2. les deux lignes à coller dessus ; 3.
// l'attente de l'agent, en direct (EnrollFlow). Le jeton naît à la fin de la
// première étape et ne vit que dans cette fenêtre.
export function AddMachine() {
  const t = useT();
  const roles = useRoles();
  const navigate = useNavigate();
  const form = useForm(emptyMachineForm);
  const { values, change } = form;
  const action = useAction();
  const formID = useId();
  const [token, setToken] = useState<TokenResponse | null>(null);
  // Les machines d'avant le jeton : l'arrivée de l'agent se reconnaît à ce qui s'y ajoute.
  const machines = useMachines();
  const join = machines.data?.join;
  const [knownIDs, setKnownIDs] = useState<string[]>([]);
  const close = () => void navigate("/machines", { replace: true });

  const create = (event: FormEvent) => {
    event.preventDefault();
    const set = values.set;
    if (set === "") {
      return;
    }
    action.run(() => createMachineToken(values.name, values.role, set), {
      topic: "all",
      onDone: (created) => {
        setKnownIDs((machines.data?.machines ?? []).map((machine) => machine.id));
        setToken(created);
      },
    });
  };

  const titles = [t("machine.step_name"), t("machine.step_install"), t("machine.step_wait")];

  if (token !== null) {
    return <EnrollFlow title={t("machine.new_title")} titles={titles} token={token} target={{ kind: "new", name: token.name, knownIDs }} onClose={close} />;
  }
  return (
    <Modal
      title={t("machine.new_title")}
      onClose={close}
      dirty={isMachineFormModified(values)}
      wide
      actions={
        <>
          <ModalCancel />
          <Button type="submit" form={formID} variant="primary" icon="plus" disabled={action.busy || join?.ready !== true || values.name.trim() === "" || values.set === ""}>
            {t("machine.create_token")}
          </Button>
        </>
      }
    >
      <WizardBar titles={titles} position={0} reached={0} canJump={false} onJump={() => undefined} />
      <form id={formID} className="modal-form" onSubmit={create}>
        <p className="secondary">{t("machine.new_subtitle")}</p>
        <JoinNeedsDomain join={join} />
        <Field label={t("machine.name_label")} htmlFor="machine-name" help={t("machine.name_help")}>
          <Input
            id="machine-name"
            type="text"
            value={values.name}
            onChange={(event) => change("name", event.target.value)}
            placeholder={t("machine.name_placeholder")}
            autoComplete="off"
            autoFocus
            required
          />
        </Field>
        <Field label={t("machine.role_label")} htmlFor="machine-role" help={t("machine.role_help")}>
          <Select
            id="machine-role"
            value={values.role}
            options={roles.map((offered) => ({ value: offered.id, label: t(`role.${offered.id}`) }))}
            onChange={(role) => change("role", role as RoleID)}
          />
        </Field>
        <Field label={t("machine.set_label")}>
          <RightsSetChoice sets={join?.sets ?? []} value={values.set} onChange={(set) => change("set", set)} />
        </Field>
        <Failure error={action.error} />
      </form>
    </Modal>
  );
}
