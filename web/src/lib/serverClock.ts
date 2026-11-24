import { formatWhen } from "./time";

// L'heure du serveur, que l'opérateur compare à celle de son téléphone avant
// de saisir le code (E02-21). Le serveur la dit une fois ; l'écart avec le
// navigateur, mesuré à la réception, la fait avancer sans la relire.

export function clockOffset(serverTime: string, receivedAt: number): number {
  return Date.parse(serverTime) - receivedAt;
}

// L'heure du serveur à l'instant now du navigateur, en heure et minute
// locales ; la date en plus quand le serveur n'est pas au même jour.
export function serverClock(offset: number, now: number): string {
  return formatWhen(new Date(now + offset).toISOString(), now);
}
