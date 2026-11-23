import { useResource, type Resource } from "../hooks/useResource";
import { api } from "./client";
import { route } from "./routes";

// L'accès de l'opérateur à l'interface. Chemin sans sujet du direct : relu
// à la reconnexion, quand tout se relit, jamais à chaque sujet.

// « native » est la connexion native (un compte et son mot de passe dans
// le produit) ; « forward » le mode derrière un SSO en amont (Authelia) :
// « SSO » dans l'interface, « mandataire » ne désignant que trusted_proxies.
type AuthMode = "none" | "native" | "forward";

// En forward, username est l'identité que le mandataire a transmise avec
// la requête, et header le nom de l'en-tête qui la porte. En native sans
// session, username est vide et enabled_at nul : le serveur ne dit rien du
// compte à qui ne s'est pas connecté.
export interface AuthState {
  mode: AuthMode;
  username: string;
  header?: string;
  enabled_at: string | null;
  password_min_length: number;
  // Une session valable accompagne la requête (native) ; toujours vrai en
  // forward, faux sans compte.
  signed_in: boolean;
  // L'identifiant de la session courante, en native connecté seulement.
  session?: string;
  // En forward, présent et vrai quand rien ne prouve que la requête passe
  // par le mandataire (pas de secret, boucle locale de confiance).
  forward_insecure?: boolean;
  // Les identités que forward_users (config.toml) admet, en forward
  // seulement ; null quand la liste est vide (toute identité du mandataire)
  // et dans les autres modes.
  allowed_users: string[] | null;
  // En native connecté, présent et vrai quand le code à six chiffres est
  // actif : la redemande le demande aussi.
  totp?: boolean;
}

// Un compte et son mot de passe, ou l'en-tête d'un mandataire ; dans les deux
// cas, le code de première configuration que la machine du produit affiche.
type AuthSetupRequest =
  | { setup_code: string; mode: "native"; username: string; password: string }
  | { setup_code: string; mode: "forward"; header: string };

const authPath = "/api/auth";

export function useAuth(): Resource<AuthState> {
  return useResource<AuthState>(authPath);
}

// Crée le compte de la première configuration. En native, la réponse pose
// le cookie de la première session : rien à confier au navigateur ensuite.
// Le serveur répond aussi combien de jetons d'API sont tombés : l'écran n'en
// dit rien, il n'y en a qu'après une commande de secours, et la
// documentation le dit.
export async function setup(body: AuthSetupRequest): Promise<AuthState> {
  return api.send<AuthState>(route("POST /api/auth/setup"), body);
}

// Ouvre une session : le serveur pose le cookie avec sa réponse. Le code est
// vide au premier écran ; quand il est actif, le serveur le demande
// (auth.totp_required) et la page ouvre le second.
export async function login(username: string, password: string, code = ""): Promise<AuthState> {
  return api.send<AuthState>(route("POST /api/auth/login"), { username, password, code });
}

// La redemande d'un geste de niveau 4 : le mot de passe, et le code s'il est
// actif. Le serveur renouvelle le cookie de la session ; le geste se rejoue.
export async function reauth(password: string, code: string): Promise<void> {
  return api.send(route("POST /api/auth/reauth"), { password, code });
}

// Un secret tiré pour l'activation du code, que rien ne garde tant qu'un
// premier code juste ne revient pas. qr_code est une image en data URI.
export interface TOTPProposal {
  secret: string;
  uri: string;
  qr_code: string;
}

// Une lecture à part, jamais relue par le direct : chaque lecture tire un
// autre secret.
export async function proposeTOTP(): Promise<TOTPProposal> {
  return api.get<TOTPProposal>("/api/auth/totp/proposal");
}

export async function enableTOTP(secret: string, code: string): Promise<void> {
  return api.send(route("POST /api/auth/totp"), { secret, code });
}

// Le serveur refuse (403) sans le mot de passe juste.
export async function disableTOTP(password: string): Promise<void> {
  return api.send(route("DELETE /api/auth/totp"), { password });
}

// Ferme la session courante ; le serveur efface le cookie.
export async function logout(): Promise<void> {
  return api.send(route("POST /api/auth/logout"));
}

// Une session ouverte, telle que le serveur la tient. source est une adresse
// IPv4 ou un /64 IPv6 ; user_agent, le texte que le navigateur a envoyé,
// borné par le serveur : il s'affiche en texte brut.
interface OpenSession {
  id: string;
  created_at: string;
  seen_at: string;
  expires_at: string;
  source: string;
  user_agent: string;
  current: boolean;
}

export interface OpenSessions {
  sessions: OpenSession[];
}

const sessionsPath = "/api/auth/sessions";

// Chemin sans sujet du direct : relu à la demande de la page. wanted
// suspend la lecture hors de la connexion native, où il n'y a pas de session.
export function useOpenSessions(wanted: boolean): Resource<OpenSessions> {
  return useResource<OpenSessions>(wanted ? sessionsPath : null);
}

export async function closeSession(id: string): Promise<void> {
  return api.send(route("DELETE /api/auth/sessions/{id}", { id }));
}

// Ferme toutes les sessions sauf la courante. Le serveur dit combien ; la
// liste relue le montre déjà.
export async function closeOtherSessions(): Promise<void> {
  await api.send(route("POST /api/auth/sessions/actions/close-others"));
}

// Ce que le serveur dit d'un changement réussi : les autres sessions sont
// fermées, la courante reste ; les jetons d'API ne tombent pas avec l'ancien
// mot de passe, l'écran propose de les révoquer.
export interface PasswordChange {
  api_tokens: number;
}

// Le serveur refuse (403) sans le mot de passe actuel juste.
export async function changePassword(current: string, password: string): Promise<PasswordChange> {
  return api.send<PasswordChange>(route("PUT /api/auth/password"), { current, password });
}
