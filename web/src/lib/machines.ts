import type { Account, Agent, Capability, Machine, ReportedCapability, RightsSet, RoleID, TokenResponse } from "../api/machines";
import type { Translate } from "../i18n/context";
import type { SelectOption } from "./select";
import { seenAgo } from "./time";

// Le sous-titre des pages qui comptent les machines : rien, une, plusieurs.
export function machinesSubtitle(t: Translate, total: number, online: number): string {
  if (total === 0) {
    return t("overview.subtitle");
  }
  if (total === 1) {
    return t("machines.subtitle_one", online);
  }
  return t("machines.subtitle", total, online);
}

// Le formulaire d'une machine neuve : son nom, son rôle (les modules qu'elle
// montre, aucun droit) et le jeu de droits de son agent, vide tant qu'aucun
// n'est choisi.
interface MachineFormValues {
  name: string;
  role: RoleID;
  set: RightsSet | "";
}

export const emptyMachineForm: MachineFormValues = { name: "", role: "generic", set: "" };

// La saisie a changé depuis le formulaire neuf : fermer la fenêtre de l'ajout
// demande alors s'il faut l'abandonner.
export function isMachineFormModified(values: MachineFormValues): boolean {
  return values.name.trim() !== "" || values.role !== emptyMachineForm.role || values.set !== emptyMachineForm.set;
}

// Ce que le bouton « Copier » de l'ajout met dans le presse-papiers : la
// commande, puis le jeton, chacun sur sa ligne. Collées ensemble, join lit la
// seconde sur le terminal sans l'afficher.
export function joinPasteText(token: Pick<TokenResponse, "command" | "token">): string {
  return `${token.command}\n${token.token}\n`;
}

// observe est toujours accordé.
export const alwaysGranted = "observe";

// La clé du libellé d'un droit : le point du nom devient « _ ».
export function capabilityLabelKey(name: string): string {
  return `machine.capability_${name.split(".").join("_")}`;
}

// Un droit en une ligne : son libellé, puis ses chemins.
export function describeCapability(t: Translate, capability: Capability): string {
  const label = t(capabilityLabelKey(capability.name));
  return capability.paths.length === 0 ? label : t("machine.right_with_paths", label, capability.paths.join(", "));
}

// Le compte de l'agent en une ligne : son nom et son uid, ou l'uid seul quand
// le compte n'a pas de nom lisible. null : l'agent n'a rien dit.
export function describeAccount(account: Account | null): string | null {
  if (account === null) {
    return null;
  }
  return account.name === "" ? String(account.uid) : `${account.name} (${account.uid})`;
}

// Le compte pour une phrase : son nom, ou son uid sans nom.
function accountLabel(account: Account | null): string {
  return account === null ? "" : account.name === "" ? String(account.uid) : account.name;
}

// Pourquoi un droit coché ne s'exerce pas : une phrase par raison. Sous root,
// un dossier refusé ne se règle pas par un chown : la phrase est autre.
export function describeUnavailable(t: Translate, reason: string, account: Account | null): string {
  if (reason === "path_denied") {
    return account?.uid === 0 ? t("machine.capability_unavailable_path_denied_root") : t("machine.capability_unavailable_path_denied", accountLabel(account));
  }
  return t(`machine.capability_unavailable_${reason}`);
}

// Les droits cochés que le compte de l'agent ne peut pas exercer, un par ligne :
// « droit : raison ». Vide quand il peut tout, ou n'a rien dit.
export function unavailableRights(t: Translate, agent: Pick<Agent, "capabilities" | "run_as">): string[] {
  return agent.capabilities
    .filter((capability: ReportedCapability) => capability.unavailable !== "")
    .map((capability) => t("machine.capability_unavailable_item", describeCapability(t, capability), describeUnavailable(t, capability.unavailable, agent.run_as)));
}

// « vu » d'une machine. En ligne, elle l'est à l'instant : son flux est
// ouvert. Le direct ne republie pas la liste à chaque signal, le dernier
// signal lu vieillirait à l'écran pendant que la machine répond.
export function machineSeen(t: Translate, machine: Pick<Machine, "online" | "last_seen_at">, now: number): string {
  if (machine.online) {
    return t("machine.seen_now");
  }
  return seenAgo(t, machine.last_seen_at, now);
}

// Une machine archivée : son agent est révoqué (supprimée en gardant
// l'historique), tout le reste demeure. Ré-enrôler la remet en service.
export function isArchived(machine: Pick<Machine, "agent">): boolean {
  return machine.agent !== null && machine.agent.revoked_at !== null;
}

// Les machines que l'on attend : les archivées restent dans la liste, mais ne
// comptent ni parmi les machines en ligne ni parmi celles en défaut.
export function liveMachines<M extends Pick<Machine, "agent">>(machines: M[]): M[] {
  return machines.filter((machine) => !isArchived(machine));
}

// Le bouton qui supprime dans la fenêtre « Supprimer la machine » : garder
// l'historique se défait (ré-enrôler), il part tout de suite ; effacer ne se
// défait pas, il attend le nom de la machine tapé tel quel.
export function canConfirmDeletion(machineName: string, typedName: string, keepHistory: boolean): boolean {
  return keepHistory || typedName === machineName;
}

// L'option d'un menu pour une machine : son nom, puis son type en discret, pour
// qu'on voie où elle tourne avant de la choisir.
// Sans type (une machine que la liste ne connaît plus), pas de mot : ne rien dire
// vaut mieux que dire « inconnu » d'une machine qu'on ne lit pas.
export function machineOption(t: Translate, machine: { id: string; name: string; kind?: Machine["kind"] | undefined }): SelectOption {
  return { value: machine.id, label: machine.name, hint: machine.kind === undefined ? undefined : t(`machine.kind_${machine.kind}`) };
}

// Le type de chaque machine de la liste, par identifiant : pour les écrans dont
// les machines viennent d'ailleurs (alertes, jetons) et ne portent pas le leur.
export function kindsByID(machines: readonly Pick<Machine, "id" | "kind">[]): ReadonlyMap<string, Machine["kind"]> {
  return new Map(machines.map((machine) => [machine.id, machine.kind]));
}
