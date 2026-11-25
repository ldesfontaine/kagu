import type { ReactNode } from "react";

import type { RefusalFix } from "../api/client";
import { Note } from "./Card";
import { LockedAction } from "./LockedAction";

// Une note qui dit qu'un droit manque (children) et porte son geste : l'écran
// sait le droit du geste qu'il montre et la machine qui doit le tenir.
// command : la ligne que le serveur a jointe ; sans elle, celle de la session.
export function MissingRight({ machineID, right, path, command, children }: { machineID: string; right: string; path?: string | undefined; command?: string | undefined; children: ReactNode }) {
  const fix: RefusalFix = { right, machine: machineID };
  if (command !== undefined) {
    fix.command = command;
  }
  return (
    <Note tone="warn">
      <p>{children}</p>
      <LockedAction fix={fix} path={path} />
    </Note>
  );
}
