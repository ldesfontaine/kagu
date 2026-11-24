import type { ReactNode } from "react";

import { Note } from "./Card";
import { LockedAction } from "./LockedAction";

// Une note qui dit qu'un droit manque (children) et porte son geste : l'écran
// sait le droit du geste qu'il montre et la machine qui doit le tenir.
export function MissingRight({ machineID, right, path, children }: { machineID: string; right: string; path?: string | undefined; children: ReactNode }) {
  return (
    <Note tone="warn">
      <p>{children}</p>
      <LockedAction fix={{ right, machine: machineID }} path={path} />
    </Note>
  );
}
