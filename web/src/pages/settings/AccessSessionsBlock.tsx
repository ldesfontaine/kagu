import { closeOtherSessions, closeSession, logout, type OpenSessions } from "../../api/auth";
import { Button } from "../../components/Button";
import { Failure } from "../../components/Failure";
import { Pill } from "../../components/Pill";
import { SettingBlock } from "../../components/SettingRow";
import { Table } from "../../components/Table";
import { useAction } from "../../hooks/useAction";
import { useNow } from "../../hooks/useNow";
import type { Resource } from "../../hooks/useResource";
import { useT } from "../../i18n/context";
import { ago } from "../../lib/time";

// Les sessions ouvertes de la connexion native : le navigateur, l'adresse,
// le dernier passage. La session courante se marque et ne se ferme que par
// « Se déconnecter », qui recharge la page : la porte montre alors la
// connexion. Le navigateur est le texte qu'il a envoyé, en texte brut. La
// section lit la liste : un changement de mot de passe la fait relire.
export function AccessSessionsBlock({ sessions, onSignedOut }: { sessions: Resource<OpenSessions>; onSignedOut: () => void }) {
  const t = useT();
  const now = useNow();
  const action = useAction();
  const list = sessions.data?.sessions ?? [];
  const hasOthers = list.some((session) => !session.current);

  const close = (id: string) => {
    action.run(() => closeSession(id), { onDone: sessions.reload });
  };
  const closeOthers = () => {
    action.run(() => closeOtherSessions(), { onDone: sessions.reload });
  };
  const signOut = () => {
    action.run(() => logout(), { onDone: onSignedOut });
  };

  return (
    <>
      <div className="setting-subhead">
        <span className="card-t">{t("auth.sessions_title")}</span>
        <span className="secondary">{t("auth.sessions_text")}</span>
      </div>
      {(sessions.error !== null || action.error !== null) && (
        <SettingBlock>
          <Failure error={action.error ?? sessions.error} />
        </SettingBlock>
      )}
      {list.length > 0 && (
        <Table>
          <thead>
            <tr>
              <th>{t("auth.session_col_browser")}</th>
              <th className="nowrap">{t("auth.session_col_source")}</th>
              <th className="nowrap">{t("auth.session_col_seen")}</th>
              <th className="th-end" />
            </tr>
          </thead>
          <tbody>
            {list.map((session) => (
              <tr key={session.id}>
                <td className="secondary">{session.user_agent === "" ? t("auth.session_no_browser") : session.user_agent}</td>
                <td className="mono nowrap">{session.source}</td>
                <td className="secondary nowrap">{ago(t, session.seen_at, now)}</td>
                <td className="td-end">
                  {session.current ? (
                    <Pill tone="ok">{t("auth.session_current")}</Pill>
                  ) : (
                    <Button variant="ghost" small disabled={action.busy} onClick={() => close(session.id)}>
                      {t("auth.session_close")}
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <SettingBlock>
        <div className="cluster">
          <Button disabled={action.busy || !hasOthers} onClick={closeOthers}>
            {t("auth.sessions_close_others")}
          </Button>
          <Button icon="x" disabled={action.busy} onClick={signOut}>
            {t("auth.logout")}
          </Button>
        </div>
      </SettingBlock>
    </>
  );
}
