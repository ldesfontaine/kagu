import { useState } from "react";

import { requestRight } from "../api/actions";
import { useAction } from "../hooks/useAction";
import { useT } from "../i18n/context";
import { Button } from "./Button";
import { Note } from "./Card";
import { Failure } from "./Failure";

// « Demander ce droit à la machine » (R-DROIT-8, ARB-1, niveau 3) : l'ordre
// right.request part signé, l'agent le refuse et le note ; la ligne constante
// d'à côté le montre ensuite à root, qui le pose après l'avoir lu. Rien ne
// s'allume ici : le geste grisé le reste jusqu'à ce que l'agent rapporte le
// droit (R-DROIT-4).
export function RequestRight({ machineID, right, value = "" }: { machineID: string; right: string; value?: string }) {
  const t = useT();
  const action = useAction();
  const [sent, setSent] = useState(false);
  const request = () => {
    action.run(() => requestRight(machineID, right, value), { topic: "actions", onDone: () => setSent(true) });
  };
  return (
    <div className="stack gap-8">
      <div>
        <Button small icon="shield" onClick={request} disabled={action.busy}>
          {t("rights.request_right")}
        </Button>
      </div>
      {sent && <Note tone="neutral">{t("rights.request_sent")}</Note>}
      <Failure error={action.error} />
    </div>
  );
}
