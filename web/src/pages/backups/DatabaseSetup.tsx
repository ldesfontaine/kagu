import { deleteBackupDestination, useBackups, type BackupDestination } from "../../api/backups";
import { reasonText } from "../../components/ActionsCard";
import { Button } from "../../components/Button";
import { Failure } from "../../components/Failure";
import { LockedAction } from "../../components/LockedAction";
import { RightPill } from "../../components/RightPill";
import { useAction } from "../../hooks/useAction";
import { useNow } from "../../hooks/useNow";
import { useT } from "../../i18n/context";
import { keyringPath, newDestinationPath } from "../../lib/backups";
import { formatWhen } from "../../lib/time";


// Ce dont la base de Kagu a besoin en plus d'un plan : la clé qui chiffre
// ses archives, et les machines qui les reçoivent. Ces deux réglages vivaient
// dans un bloc à part ; ils sont maintenant sur la ligne de la base, là où on
// regarde si elle est sauvegardée.
export function DatabaseSetup() {
  const t = useT();
  const now = useNow();
  const backups = useBackups();
  const action = useAction();
  if (backups.data === null) {
    return null;
  }
  const { keyring, destinations } = backups.data;
  const remove = (destination: BackupDestination) => {
    action.run(() => deleteBackupDestination(destination.id), { topic: "backups" });
  };
  return (
    <div className="backup-setup">
      <div className="backup-setup-line">
        <div className="backup-setup-say">
          <b>{t("backup.keyring_title")}</b>
          <span className="secondary">{keyring === null ? t("backup.keyring_none") : `${t("backup.fingerprint")} ${keyring.fingerprint} · ${formatWhen(keyring.created_at, now)}`}</span>
        </div>
        <Button small icon="shield" to={keyringPath}>
          {keyring === null ? t("backup.keyring_create") : t("backup.keyring_replace")}
        </Button>
      </div>
      <div className="backup-setup-line">
        <div className="backup-setup-say">
          <b>{t("backup.destination_title")}</b>
          {destinations.length === 0 && <span className="secondary">{t("backup.destination_none")}</span>}
        </div>
        <Button small icon="plus" to={newDestinationPath}>
          {t("backup.destination_add")}
        </Button>
      </div>
      {destinations.map((destination) => (
        <div key={destination.id} className="backup-setup-line backup-setup-sub">
          <div className="backup-setup-say">
            <span className="medium">{destination.name}</span>
            <span className="secondary">
              {destination.machine_name} · <span className="mono">{destination.path}</span>
            </span>
            {destination.right === "unavailable" && <span className="secondary">{reasonText(t, destination.right_reason ?? "")}</span>}
          </div>
          <span className="backup-setup-end">
            <RightPill small state={destination.right} />
            {destination.right === "missing" && <LockedAction fix={{ right: "backup.receive", machine: destination.machine_id }} path={destination.path} short />}
            <Button small variant="ghost" icon="x" disabled={action.busy} onClick={() => remove(destination)}>
              {t("backup.destination_delete")}
            </Button>
          </span>
        </div>
      ))}
      <Failure error={action.error} />
    </div>
  );
}
