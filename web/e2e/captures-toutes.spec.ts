import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";

import type { Page } from "@playwright/test";

import { linksOf, openPage } from "./support/actions";
import { type Capture, bindFromParent, captureFile, findForbidden, formats, menuOf, parseForbidden, renderIndex, routesWithoutCapture, staleExceptions } from "./support/captures";
import { expect, test } from "@playwright/test";
import { declaredRoutes, routeOfPath, unreachedRoutes } from "./support/routes";

// Toutes les pages de l'application en mode sombre, sur ordinateur et sur
// téléphone, pleine page : docs/captures/<page>-<format>.webp et docs/captures.md.
// La liste vient du routeur (declaredRoutes), pas d'une liste tapée ; une route
// à paramètre prend le premier identifiant que le serveur rend dans ses liens.
// Données fictives seulement. Hors `make ci` : lancé par `scripts/captures.sh`,
// qui pose E2E_CAPTURES=1, les motifs interdits et le commit.
test.skip(process.env.E2E_CAPTURES !== "1", "captures demandées par E2E_CAPTURES=1");
test.use({ colorScheme: "dark" });

const docs = new URL("../../docs/", import.meta.url);
const folder = new URL("captures/", docs);
// Les menus « … » ouverts par page : assez pour atteindre chaque sorte de ligne d'une liste.
const maxMenus = 40;
const manifestFile = new URL("./.results/captures-manifest.json", import.meta.url);

interface Manifest {
  captures: Capture[];
  menuOrder: string[];
}

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(`${name} n'est pas posée : lancer par scripts/captures.sh`);
  }
  return value;
}

const forbidden = () => parseForbidden(readFileSync(required("CAPTURES_FORBIDDEN_FILE"), "utf8"));

// Playwright ne sait pas écrire du WebP : Chromium l'encode lui-même, par un
// canevas. Pas d'outil de plus sur la machine.
async function toWebp(converter: Page, png: Buffer): Promise<Buffer> {
  const encoded = await converter.evaluate(async (source) => {
    const image = new Image();
    image.src = `data:image/png;base64,${source}`;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    canvas.getContext("2d")?.drawImage(image, 0, 0);
    const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/webp", 0.85));
    if (blob === null) {
      throw new Error(`le canevas ${canvas.width}×${canvas.height} ne s'encode pas en WebP`);
    }
    const bytes = new Uint8Array(await blob.arrayBuffer());
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary);
  }, png.toString("base64"));
  return Buffer.from(encoded, "base64");
}

// Les adresses que proposent les menus « … » : fermés, leurs choix ne sont pas
// dans la page. Les ouvrir un à un les y met ; Échap les referme.
async function menuLinksOf(page: Page): Promise<string[]> {
  const hrefs: string[] = [];
  // Une fenêtre ouverte couvre la page : ses menus ne se cliquent pas.
  if ((await page.locator("dialog[open]").count()) > 0) {
    return hrefs;
  }
  const openers = page.locator("main button[aria-haspopup=menu]:visible:not([disabled])");
  for (let index = 0; index < Math.min(await openers.count(), maxMenus); index++) {
    await openers.nth(index).click();
    const links = page.locator("[role=menu] a[role=menuitem]");
    hrefs.push(...(await links.evaluateAll((anchors) => anchors.map((anchor) => anchor.getAttribute("href") ?? ""))));
    await page.keyboard.press("Escape");
  }
  return hrefs.filter((href) => href.startsWith("/"));
}

// Les adresses prises en exemple : le premier identifiant de chaque forme.
// Chaque page ouverte offre ses liens ; une route sans lien (une fenêtre de
// modification) prend l'identifiant de sa route-mère.
async function discoverPaths(page: Page, patterns: string[]): Promise<Record<string, string>> {
  const resolved: Record<string, string> = {};
  const queue: string[] = [];
  const resolve = (pattern: string, path: string) => {
    resolved[pattern] = path;
    queue.push(path);
  };
  for (const pattern of patterns.filter((route) => !route.includes(":"))) {
    resolve(pattern, pattern);
  }
  for (;;) {
    while (queue.length > 0) {
      const path = queue.shift() ?? "/";
      const links = await linksOf(page, path);
      for (const href of [...links, ...(await menuLinksOf(page))]) {
        const pathname = href.split("?")[0] ?? href;
        const pattern = routeOfPath(patterns, pathname);
        if (pattern !== undefined && !(pattern in resolved)) {
          resolve(pattern, pathname);
        }
      }
    }
    const bound = patterns.filter((pattern) => !(pattern in resolved) && bindFromParent(pattern, resolved) !== undefined);
    for (const pattern of bound) {
      resolve(pattern, bindFromParent(pattern, resolved) ?? pattern);
    }
    if (bound.length === 0) {
      return resolved;
    }
  }
}

// Le nom de la page : le titre de la fenêtre ouverte s'il y en a une (la page
// dessous porte le même titre que sa route-mère), sinon le h1 de la page.
async function titleOf(page: Page): Promise<string> {
  const dialogTitle = page.locator("dialog[open] .modal-title").first();
  const heading = (await dialogTitle.innerText().catch(() => "")) || (await page.locator("main h1").first().innerText().catch(() => ""));
  const title = heading.trim().replace(/\s+/g, " ");
  return title !== "" ? title : await page.title();
}

test("prendre les captures de toutes les routes", async ({ page, context }) => {
  test.setTimeout(Number(process.env.E2E_TEST_TIMEOUT ?? 30 * 60_000));
  await page.addInitScript(() => localStorage.setItem("theme", "dark"));
  const patterns = [...new Set(declaredRoutes())].filter((route) => !(route in unreachedRoutes));
  const paths = await discoverPaths(page, patterns);
  const patternsWithoutPath = patterns.filter((route) => !(route in paths));
  expect(patternsWithoutPath, "routes à paramètre sans identifiant dans les liens de l'interface").toEqual([]);

  await openPage(page, "/");
  const menuEntries = await page.locator("#side a.nav-item").evaluateAll((anchors) =>
    anchors.map((anchor) => ({ href: anchor.getAttribute("href") ?? "", label: (anchor.querySelector("span")?.textContent ?? "").trim() })),
  );
  const patternsOfText = forbidden();
  const converter = await context.newPage();
  mkdirSync(folder, { recursive: true });
  const captures: Capture[] = [];
  const faults: string[] = [];
  for (const route of patterns) {
    const path = paths[route] ?? route;
    let title = "";
    for (const format of formats) {
      await page.setViewportSize(format.viewport);
      try {
        await openPage(page, path);
        title = await titleOf(page);
        const found = findForbidden(`${await page.title()}\n${await page.locator("body").innerText()}`, patternsOfText);
        if (found.length > 0) {
          faults.push(`${route} (${format.name}) : la page porte un motif interdit (${found.join(", ")}), capture refusée`);
          continue;
        }
        const png = await page.screenshot({ fullPage: true, animations: "disabled" });
        writeFileSync(new URL(captureFile(route, format.name), folder), await toWebp(converter, png));
      } catch (error) {
        faults.push(`${route} (${format.name}) : ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    captures.push({ route, path, title, menu: menuOf(route, menuEntries) });
  }
  await converter.close();
  // Une page fautive reste hors du manifeste : le test suivant la dit absente.
  const refused = new Set(faults.map((fault) => fault.split(" ")[0]));
  const manifest: Manifest = { captures: captures.filter((capture) => !refused.has(capture.route)), menuOrder: menuEntries.map((entry) => entry.label) };
  mkdirSync(new URL(".", manifestFile), { recursive: true });
  writeFileSync(manifestFile, JSON.stringify(manifest, null, 2));
  expect(faults, "captures manquantes ou refusées").toEqual([]);
});

test("R-CAPTURES-1 : chaque route du routeur a une capture par format, ou son écart", () => {
  const manifest = JSON.parse(readFileSync(manifestFile, "utf8")) as Manifest;
  const declared = [...new Set(declaredRoutes())];
  const taken = manifest.captures.map((capture) => capture.route);
  expect(routesWithoutCapture(declared, taken, unreachedRoutes), "routes du routeur sans capture").toEqual([]);
  expect(staleExceptions(declared, taken, unreachedRoutes), "écarts qui ne servent plus").toEqual([]);

  // Les captures des pages disparues se suppriment : le dossier ne garde que celles d'aujourd'hui.
  const expected = new Set(taken.flatMap((route) => formats.map((format) => captureFile(route, format.name))));
  for (const file of readdirSync(folder)) {
    if (!expected.has(file)) {
      rmSync(new URL(file, folder));
    }
  }
  for (const file of expected) {
    expect(() => readFileSync(new URL(file, folder)), `fichier ${file}`).not.toThrow();
  }

  const index = renderIndex(manifest.captures, manifest.menuOrder, unreachedRoutes, { date: required("CAPTURES_DATE"), commit: required("CAPTURES_COMMIT") });
  expect(findForbidden(index, forbidden()), "motifs interdits dans docs/captures.md").toEqual([]);
  writeFileSync(new URL("captures.md", docs), index);
});
