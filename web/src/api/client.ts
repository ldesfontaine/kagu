import type { WriteRoute } from "./routes";

// Ce que l'API rend, tel quel : des faits, des instants ISO en UTC, des
// durées en secondes ou en millisecondes. Le formatage vit dans le front.

// Le seul endroit qui parle à l'API : JSON, même origine, une erreur
// typée qui porte le code du serveur. Ce code est une clé du catalogue
// quand l'opérateur doit le lire.
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    // Le corps de la réponse, quand le refus porte plus qu'une clé (la
    // liste de ce qui lie un service qu'on voulait supprimer).
    readonly payload: unknown = null,
  ) {
    super(code);
  }
}

// Ce qui lève un refus, tel que le serveur le joint (fix) : le droit qui
// manque et la machine dont l'agent doit le tenir, et la ligne à lancer en
// root sur elle. Pour une ancre, la ligne seule ; exact : elle pose la valeur
// de l'ordre (sinon « trust list », et l'écran renvoie à la fiche).
export interface RefusalFix {
  right?: string;
  machine?: string;
  command?: string;
  exact?: boolean;
}

// Toute écriture part en JSON avec un corps, {} quand elle n'a rien à
// dire : le serveur peut ainsi exiger ce type sans exception. Un geste de
// niveau 4 refusé faute de redemande ouvre la fenêtre de redemande, puis se
// rejoue une fois si elle a réussi.
async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  try {
    return await send<T>(method, path, body);
  } catch (failure) {
    if (failure instanceof ApiError && isReauthRequired(failure) && reauthAsker !== null && (await reauthAsker())) {
      return send<T>(method, path, body);
    }
    throw failure;
  }
}

async function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, credentials: "same-origin" };
  // Toute écriture part en JSON, même sans rien à dire : le serveur refuse
  // une écriture qui n'en porte pas, c'est sa garde même-origine.
  if (method !== "GET") {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(body ?? {});
  }
  const response = await fetch(path, init);
  if (response.status === 204) {
    return undefined as T;
  }
  if (!response.ok) {
    const payload = await errorPayload(response);
    const failure = new ApiError(response.status, errorCode(payload), payload);
    if (isSessionLost(failure)) {
      announceSessionLost();
    }
    throw failure;
  }
  return (await response.json()) as T;
}

// Une session morte en cours d'usage (2 h sans geste, 12 h au plus) fait
// répondre 401 « unauthorized » à toute route de l'opérateur. Un mot de
// passe faux à la connexion a sa propre clé : il ne compte pas.
function isSessionLost(error: ApiError): boolean {
  return error.status === 401 && error.code === "unauthorized";
}

// Qui écoute la perte de la session : la porte d'accès, pour revenir à la
// connexion sans que chaque page s'en occupe.
const sessionLostListeners = new Set<() => void>();

export function onSessionLost(listener: () => void): () => void {
  sessionLostListeners.add(listener);
  return () => {
    sessionLostListeners.delete(listener);
  };
}

function announceSessionLost() {
  for (const listener of sessionLostListeners) {
    listener();
  }
}

// En native, un geste de niveau 4 sans mot de passe redonné depuis cinq
// minutes répond 403 « auth.reauth_required » (R-A2-7). En SSO, jamais.
function isReauthRequired(error: ApiError): boolean {
  return error.status === 403 && error.code === "auth.reauth_required";
}

// Qui ouvre la fenêtre de redemande : la porte d'accès. Il rend vrai quand
// la redemande a réussi, faux quand la personne a renoncé.
type ReauthAsker = () => Promise<boolean>;

let reauthAsker: ReauthAsker | null = null;

export function onReauthRequired(asker: ReauthAsker): () => void {
  reauthAsker = asker;
  return () => {
    if (reauthAsker === asker) {
      reauthAsker = null;
    }
  };
}

async function errorPayload(response: Response): Promise<unknown> {
  try {
    return (await response.json()) as unknown;
  } catch {
    return null;
  }
}

function errorCode(payload: unknown): string {
  if (typeof payload === "object" && payload !== null && "error" in payload && typeof payload.error === "string") {
    return payload.error;
  }
  return "internal";
}

// Les identifiants du serveur : hexadécimaux (sondes, tâches, composants),
// UUID (machines), « local », préfixés (svc_, unit_, prj_, apl_), entiers
// (alertes), et « machine:identifiant Docker » pour un conteneur. Ni point,
// ni barre, ni « ? » ni « # » : rien qui change le chemin d'une requête.
const idPattern = /^[A-Za-z0-9_:-]{1,128}$/;

// segment prépare un paramètre de route (ou de requête) à entrer dans un
// chemin d'API. react-router rend « %2F » en « / » et le navigateur résout
// « ../ » avant d'envoyer : un lien forgé ferait partir la requête de la
// page vers une autre ressource. Ce qui n'a pas la forme d'un identifiant
// lève la même erreur qu'une ressource absente.
export function segment(value: string): string {
  if (!idPattern.test(value)) {
    throw new ApiError(404, "not_found");
  }
  return encodeURIComponent(value);
}

// Les lectures passent un chemin ; les écritures, une route de routes.ts :
// aucune écriture ne part d'un chemin écrit à la main.
export const api = {
  get: <T>(path: string) => call<T>("GET", path),
  send: <T>(write: WriteRoute, body?: unknown) => call<T>(write.method, write.path, body),
};

// Ce qui n'est pas un refus du serveur (réseau coupé, levée imprévue) se
// dit comme une erreur interne.
export function failureOf(error: unknown): ApiError {
  return error instanceof ApiError ? error : new ApiError(0, "internal");
}

// La clé à afficher pour une erreur : celle du serveur si c'est un refus,
// sinon le message générique.
export function errorKey(error: unknown): string {
  if (error instanceof ApiError && error.code.includes(".")) {
    return error.code;
  }
  return "error.internal";
}
