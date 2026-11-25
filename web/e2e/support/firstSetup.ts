import type { Page } from "@playwright/test";

import { label } from "./catalog";

// Le carré à scanner de la marche 3 : un PNG d'un pixel, et un secret inventé.
const sampleTOTPProposal = {
  secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
  uri: "otpauth://totp/Kagu:admin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
  qr_code: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAAAAAA6fptVAAAACklEQVR4nGNgAAAAAgABSK+kcQAAAABJRU5ErkJggg==",
};

// La première configuration, simulée côté navigateur : le serveur des données
// fictives a déjà un compte. Le jeton et les commandes sont inventés (aucun
// ne vaut quoi que ce soit) ; l'écran, lui, est le vrai.
export async function mockFirstSetup(page: Page, address: { local: boolean; suggestion: string } = { local: false, suggestion: "" }): Promise<void> {
  await page.route("**/api/auth", (route) =>
    route.fulfill({ json: { mode: "none", username: "", enabled_at: null, password_min_length: 12, signed_in: false, allowed_users: null } }),
  );
  await page.route("**/api/auth/setup", (route) =>
    route.fulfill({ json: { mode: "native", username: "admin", enabled_at: new Date().toISOString(), password_min_length: 12, signed_in: true, allowed_users: null, api_tokens_revoked: 0 } }),
  );
  await page.route("**/api/auth/totp/proposal", (route) => route.fulfill({ json: sampleTOTPProposal }));
  await page.route("**/api/machines/local-enrollment", (route) =>
    route.fulfill({
      status: 201,
      json: {
        name: "kagu",
        token: "kg_exemple_de_jeton_inventé_0000",
        steps: [
          { id: "prepare", command: "useradd --system --home-dir /var/lib/kagu-agent --shell /usr/sbin/nologin kagu-agent\ninstall -d -m 0700 -o kagu-agent -g kagu-agent /var/lib/kagu-agent" },
          { id: "enroll", command: "printf '%s\\n' 'kg_exemple_de_jeton_inventé_0000' | sudo -u kagu-agent /var/lib/kagu-agent/bin/current agent -server https://kagu.exemple.fr" },
          { id: "unit", command: "cat > /etc/systemd/system/kagu-agent.service <<'EOF'\n[Unit]\nDescription=Kagu (agent)\n[Service]\nUser=kagu-agent\nEOF\nsystemctl daemon-reload\nsystemctl enable --now kagu-agent.service" },
        ],
        proxmox_commands: "",
        expires_at: new Date(Date.now() + 3_600_000).toISOString(),
        url_local: address.local,
        url_suggestion: address.suggestion,
      },
    }),
  );
}

// Crée le compte du formulaire de première configuration, avec un code
// inventé : la route est simulée. La marche 3 (le code à six chiffres) est
// passée par « Plus tard ».
export async function createFirstAccount(page: Page): Promise<void> {
  await page.locator("#auth-setup-code").fill("12345678");
  await page.locator("#auth-username").fill("admin");
  await page.locator("#auth-password").fill("une-phrase-de-passe-de-test");
  await page.locator("#auth-confirm").fill("une-phrase-de-passe-de-test");
  await page.locator("form button[type=submit]").click();
  await page.getByRole("button", { name: label("auth.totp_later") }).click();
}
