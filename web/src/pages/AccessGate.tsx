import { useEffect, useState, type ReactNode } from "react";

import { useAuth } from "../api/auth";
import { onReauthRequired, onSessionLost } from "../api/client";
import { ConfirmGesture } from "../components/ConfirmGesture";
import { Failure } from "../components/Failure";
import { useT } from "../i18n/context";
import { needsFirstSetup, needsSignIn, reauthConfirmOf } from "../lib/auth";
import { AccessPage } from "./AccessPage";
import { FirstSetup } from "./FirstSetup";
import { Login } from "./Login";

// La porte de l'interface : sans compte, la première configuration ; en
// connexion native sans session, la connexion ; sinon l'interface. Rien ne
// s'affiche avant la réponse du serveur. Une session qui meurt en cours
// d'usage fait relire l'accès : la porte revient d'elle-même à la connexion,
// et l'interface, démontée, relira tout à la suivante. Un geste de niveau 4
// refusé faute de redemande ouvre ici la fenêtre de redemande : réussie, le
// client rejoue le geste ; abandonnée, le refus revient à la page.
export function AccessGate({ children }: { children: ReactNode }) {
  const t = useT();
  const access = useAuth();
  const reload = access.reload;
  useEffect(() => onSessionLost(reload), [reload]);
  const [answerReauth, setAnswerReauth] = useState<((done: boolean) => void) | null>(null);
  useEffect(() => onReauthRequired(() => new Promise<boolean>((resolve) => setAnswerReauth(() => resolve))), []);
  const finishReauth = (done: boolean) => {
    answerReauth?.(done);
    setAnswerReauth(null);
  };

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
  return (
    <>
      {children}
      {answerReauth !== null && (
        <ConfirmGesture
          confirm={reauthConfirmOf(access.data)}
          title={t("auth.reauth_title")}
          question={t("auth.reauth_why")}
          confirmLabel={t("auth.reauth_confirm")}
          perform={() => Promise.resolve()}
          onDone={() => finishReauth(true)}
          onClose={() => finishReauth(false)}
        />
      )}
    </>
  );
}
