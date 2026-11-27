import type { ReactNode } from "react";
import { Navigate, useParams } from "react-router";

import { useMachines, type Machine, type MachinesResponse } from "../../api/machines";

// Une fenêtre de la fiche d'une machine, à l'adresse /machines/:id/… : la
// machine que l'adresse nomme, avec la liste lue en même temps. Rien tant
// que la liste se lit ; retour à la liste si la machine n'y est plus.
export function RoutedMachine({ children }: { children: (machine: Machine, machines: MachinesResponse) => ReactNode }) {
  const { id = "" } = useParams();
  const machines = useMachines();
  const current = machines.data?.machines.find((machine) => machine.id === id);
  if (machines.data && !current) {
    return <Navigate to="/machines" replace />;
  }
  return current && machines.data ? children(current, machines.data) : null;
}
