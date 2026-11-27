// Ce que les captures de toutes les pages ont de pur : les noms de fichier, le
// rangement par menu, la garde des données réelles et l'index Markdown. Le
// navigateur est dans captures-toutes.spec.ts ; ici rien ne le touche, pour
// que captures.test.ts le vérifie sans serveur.

export const formats = [
  { name: "ordinateur", viewport: { width: 1280, height: 900 } },
  { name: "telephone", viewport: { width: 390, height: 844 } },
] as const;

export type FormatName = (typeof formats)[number]["name"];

export interface MenuEntry {
  href: string;
  label: string;
}

export interface Capture {
  route: string;
  // L'adresse prise en exemple : le premier identifiant que le serveur rend.
  path: string;
  title: string;
  menu: string;
}

export const otherMenu = "Autres pages";

// `/machines/:id/:tab` -> `machines-id-tab`. La racine est l'accueil.
export function captureName(route: string): string {
  const words = route.split("/").filter((segment) => segment !== "").map((segment) => segment.replace(/^:/, ""));
  return words.length === 0 ? "accueil" : words.join("-");
}

export function captureFile(route: string, format: FormatName): string {
  return `${captureName(route)}-${format}.webp`;
}

function segmentsOf(path: string): string[] {
  return path.split("/").filter((segment) => segment !== "");
}

// L'entrée du menu qui porte une route : la plus longue dont l'adresse est un
// préfixe de segments. L'accueil (`/`) n'est le menu que de `/`.
export function menuOf(route: string, entries: MenuEntry[]): string {
  const wanted = segmentsOf(route);
  let best: MenuEntry | undefined;
  let bestLength = -1;
  for (const entry of entries) {
    const own = segmentsOf(entry.href);
    const carries = own.length === 0 ? wanted.length === 0 : own.length <= wanted.length && own.every((segment, index) => segment === wanted[index]);
    if (carries && own.length > bestLength) {
      best = entry;
      bestLength = own.length;
    }
  }
  return best?.label ?? otherMenu;
}

// Les routes à paramètres qui n'ont pas de lien dans l'interface se déduisent
// d'une route-mère déjà résolue : `/machines/:id/reenroller` prend l'identifiant
// de `/machines/:id`. Rend undefined si une route-mère manque ou si un
// paramètre reste sans valeur.
export function bindFromParent(route: string, resolved: Record<string, string>): string | undefined {
  const segments = segmentsOf(route);
  for (let length = segments.length - 1; length >= 1; length--) {
    const parent = `/${segments.slice(0, length).join("/")}`;
    const concrete = resolved[parent];
    if (concrete === undefined) {
      continue;
    }
    const rest = segments.slice(length);
    if (rest.some((segment) => segment.startsWith(":"))) {
      return undefined;
    }
    return `${concrete}/${rest.join("/")}`;
  }
  return undefined;
}

// Les routes du routeur ni prises ni écartées : ce que le test qui ferme le
// ticket refuse.
export function routesWithoutCapture(declared: string[], taken: string[], exceptions: Record<string, string>): string[] {
  return declared.filter((route) => !taken.includes(route) && !(route in exceptions));
}

// Une exception à une route qui n'existe plus ou qui est prise malgré tout est
// une ligne périmée.
export function staleExceptions(declared: string[], taken: string[], exceptions: Record<string, string>): string[] {
  return Object.keys(exceptions).filter((route) => !declared.includes(route) || taken.includes(route));
}

// Les motifs interdits (un par ligne, expression régulière insensible à la
// casse) : le script en fait un fichier, la page et l'index sont lus contre lui.
export function parseForbidden(fileContent: string): RegExp[] {
  return fileContent
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => new RegExp(line, "i"));
}

export function findForbidden(text: string, patterns: RegExp[]): string[] {
  return patterns.filter((pattern) => pattern.test(text)).map((pattern) => pattern.source);
}

export interface IndexHeader {
  date: string;
  commit: string;
}

// docs/captures.md : les pages groupées par menu, dans l'ordre du menu, puis
// celles qu'aucune capture ne montre. Le chemin des images est relatif à docs/.
export function renderIndex(captures: Capture[], menuOrder: string[], exceptions: Record<string, string>, header: IndexHeader): string {
  const lines = [
    "# Captures de toutes les pages",
    "",
    `Prises le ${header.date} au commit \`${header.commit}\`, en mode sombre, sur les données fictives du serveur de démonstration.`,
    "Fichier généré par `scripts/captures.sh` : ne pas l'éditer.",
    "",
  ];
  const order = [...menuOrder, otherMenu];
  for (const menu of order) {
    const pages = captures.filter((capture) => capture.menu === menu);
    if (pages.length === 0) {
      continue;
    }
    lines.push(`## ${menu}`, "");
    for (const page of pages) {
      lines.push(
        `### ${page.title}`,
        "",
        `Route : \`${page.route}\` (exemple : \`${page.path}\`)`,
        "",
        "| Ordinateur (1280 × 900) | Téléphone (390 × 844) |",
        "| --- | --- |",
        `| ![${page.title}, ordinateur](captures/${captureFile(page.route, "ordinateur")}) | ![${page.title}, téléphone](captures/${captureFile(page.route, "telephone")}) |`,
        "",
      );
    }
  }
  const skipped = Object.entries(exceptions);
  if (skipped.length > 0) {
    lines.push("## Pages sans capture", "", "| Route | Raison |", "| --- | --- |");
    for (const [route, reason] of skipped) {
      lines.push(`| \`${route}\` | ${reason} |`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
