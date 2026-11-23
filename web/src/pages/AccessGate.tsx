import { useEffect, type ReactNode } from "react";

import { useAuth } from "../api/auth";
import { onSessionLost } from "../api/client";
import { Failure } from "../components/Failure";
import { needsFirstSetup, needsSignIn } from "../lib/auth";
import { AccessPage } from "./AccessPage";
import { FirstSetup } from "./FirstSetup";
import { Login } from "./Login";

// La porte de l'interface : sans compte, la première configuration ; en
// connexion native sans session, la connexion ; sinon l'interface. Rien ne
// s'affiche avant la réponse du serveur. Une session qui meurt en cours
// d'usage fait relire l'accès : la porte revient d'elle-même à la connexion,
// et l'interface, démontée, relira tout à la suivante.
export function AccessGate({ children }: { children: ReactNode }) {
  const access = useAuth();
  const reload = access.reload;
  useEffect(() => onSessionLost(reload), [reload]);

  if (access.data === null && access.error === null) {
    return null;
  }
  if (access.data === null) {
    return (
      <AccessPage>
        <Failure error={access.error} />
      </AccessPage>
    );
  }
  if (needsFirstSetup(access.data)) {
    return <FirstSetup state={access.data} onConfigured={reload} />;
  }
  if (needsSignIn(access.data)) {
    return <Login onSignedIn={reload} />;
  }
  return children;
}
