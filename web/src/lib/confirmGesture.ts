// Ce que la fenêtre de confirmation d'un geste fait confirmer (brique B-4) :
// un clic (un niveau 2 qui se rattrape), le plan de ce qui part avec, la
// saisie du nom, la redemande du mot de passe (niveau 4), la demande d'un
// jeton. Seul « reauth » est branché ; les autres arrivent avec leurs fiches
// (D1, E3, G2), dans ce même type et la même fenêtre.
export type Confirm =
  | { mode: "click" }
  | { mode: "plan" }
  | { mode: "typeName"; name: string }
  | ReauthConfirm
  | { mode: "request" };

// En SSO, rien n'est redemandé (R-A2-8) ; en native, le mot de passe, et le
// code quand il est actif (R-A2-7). Le serveur le dit, l'écran ne le devine
// pas : AuthState.mode et AuthState.totp.
export interface ReauthConfirm {
  mode: "reauth";
  sso: boolean;
  code: boolean;
}

export interface ReauthAnswer {
  password: string;
  code: string;
}

// reauthThenPerform redonne le mot de passe (et le code s'il est demandé),
// puis lance le geste. Une redemande refusée arrête tout : le geste ne part
// pas. En SSO, le geste part seul.
export async function reauthThenPerform(
  confirm: ReauthConfirm,
  answer: ReauthAnswer,
  sendReauth: (password: string, code: string) => Promise<void>,
  perform: () => Promise<void>,
): Promise<void> {
  if (!confirm.sso) {
    await sendReauth(answer.password, confirm.code ? answer.code : "");
  }
  await perform();
}
