import { useEffect, useState } from "react";

import { readServerTime } from "../api/auth";
import { useT } from "../i18n/context";
import { clockOffset, serverClock } from "../lib/serverClock";
import { useNow } from "./useNow";

// La phrase « Heure du serveur : 14:32 » de l'écran du code, qui avance avec
// la minute. Indéfinie tant que l'heure n'est pas lue : l'écran se passe de
// la phrase plutôt que d'afficher une erreur, le code reste jugé par le serveur.
export function useServerTime(): string | undefined {
  const t = useT();
  const now = useNow();
  const [offset, setOffset] = useState<number | null>(null);
  useEffect(() => {
    readServerTime().then(
      (serverTime) => {
        if (serverTime !== undefined) {
          setOffset(clockOffset(serverTime, Date.now()));
        }
      },
      () => undefined,
    );
  }, []);
  return offset === null ? undefined : t("auth.server_time", serverClock(offset, now));
}
