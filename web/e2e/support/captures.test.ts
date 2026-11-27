import { describe, expect, it } from "vitest";

import { bindFromParent, captureFile, captureName, findForbidden, menuOf, otherMenu, parseForbidden, renderIndex, routesWithoutCapture, staleExceptions } from "./captures";
import { declaredRoutes, routeOfPath, unreachedRoutes } from "./routes";

const menu = [
  { href: "/", label: "Vue d'ensemble" },
  { href: "/machines", label: "Machines" },
  { href: "/services", label: "Services" },
  { href: "/parametres", label: "Paramètres" },
];

describe("noms de capture", () => {
  it("donne un nom par route, deux formats par route", () => {
    expect(captureName("/")).toBe("accueil");
    expect(captureName("/machines/:id/:tab")).toBe("machines-id-tab");
    expect(captureFile("/machines/:id", "telephone")).toBe("machines-id-telephone.webp");
  });

  it("ne donne jamais le même nom à deux routes du routeur", () => {
    const routes = [...new Set(declaredRoutes())];
    expect(new Set(routes.map(captureName)).size).toBe(routes.length);
  });
});

describe("menu d'une route", () => {
  it("prend l'entrée la plus longue qui la porte", () => {
    expect(menuOf("/machines/:id/proxmox", menu)).toBe("Machines");
    expect(menuOf("/services/annuaire/:id", menu)).toBe("Services");
  });

  it("garde l'accueil pour la racine seule", () => {
    expect(menuOf("/", menu)).toBe("Vue d'ensemble");
    expect(menuOf("/journal", menu)).toBe(otherMenu);
  });
});

describe("identifiants des routes sans lien", () => {
  it("prend celui de la route-mère", () => {
    expect(bindFromParent("/machines/:id/reenroller", { "/machines/:id": "/machines/m1" })).toBe("/machines/m1/reenroller");
  });

  it("refuse un paramètre resté sans valeur", () => {
    expect(bindFromParent("/machines/:id/:tab", { "/machines/:id": "/machines/m1" })).toBeUndefined();
    expect(bindFromParent("/sauvegardes/plans/:subject/modifier", {})).toBeUndefined();
  });

  it("sert « nouvelle » avant le paramètre", () => {
    expect(routeOfPath(["/machines/nouvelle", "/machines/:id"], "/machines/nouvelle")).toBe("/machines/nouvelle");
    expect(routeOfPath(["/machines/nouvelle", "/machines/:id"], "/machines/m1")).toBe("/machines/:id");
  });
});

// R-CAPTURES-1 : le test qui ferme refuse une route sans capture ; ces cas le
// montrent sur des listes écrites ici, le spec le joue sur le routeur.
describe("R-CAPTURES-1", () => {
  const declared = ["/", "/machines", "/machines/:id", "/machines/:id/proxmox"];
  const exceptions = { "/machines/:id/proxmox": "pas dans les données fictives" };

  it("passe quand chaque route est prise ou écartée", () => {
    expect(routesWithoutCapture(declared, ["/", "/machines", "/machines/:id"], exceptions)).toEqual([]);
  });

  it("refuse une route sans capture ni écart", () => {
    expect(routesWithoutCapture(declared, ["/", "/machines"], exceptions)).toEqual(["/machines/:id"]);
  });

  it("refuse un écart qui ne sert plus", () => {
    expect(staleExceptions(declared, ["/machines/:id/proxmox"], exceptions)).toEqual(["/machines/:id/proxmox"]);
    expect(staleExceptions(["/"], [], exceptions)).toEqual(["/machines/:id/proxmox"]);
    expect(staleExceptions(declared, [], exceptions)).toEqual([]);
  });

  it("n'écarte que des routes du routeur", () => {
    expect(staleExceptions(declaredRoutes().concat(Object.keys(unreachedRoutes)), [], unreachedRoutes)).toEqual([]);
  });
});

describe("garde des données réelles", () => {
  const patterns = parseForbidden("ldesfontaine\n(^|[^0-9.])10\\.77\\.\nmachine-reelle\n");

  it("refuse le domaine, le plan privé et un nom de machine", () => {
    expect(findForbidden("serveur ldesfontaine.example", patterns)).toHaveLength(1);
    expect(findForbidden("joint à 10.77.50.14", patterns)).toHaveLength(1);
    expect(findForbidden("Machine-Reelle en ligne", patterns)).toHaveLength(1);
  });

  it("laisse passer les adresses d'exemple et les versions", () => {
    expect(findForbidden("192.0.2.10 et v110.77.1 et 192.0.2.177", patterns)).toEqual([]);
  });
});

describe("index des captures", () => {
  const captures = [
    { route: "/machines", path: "/machines", title: "Machines", menu: "Machines" },
    { route: "/", path: "/", title: "Vue d'ensemble", menu: "Vue d'ensemble" },
  ];
  const index = renderIndex(captures, ["Vue d'ensemble", "Machines"], { "/machines/:id/proxmox": "absente des données" }, { date: "2026-11-27", commit: "abc1234" });

  it("porte la date et le commit en tête", () => {
    expect(index.split("\n").slice(0, 4).join("\n")).toContain("2026-11-27 au commit `abc1234`");
  });

  it("groupe par menu, dans l'ordre du menu, avec les deux formats", () => {
    expect(index.indexOf("## Vue d'ensemble")).toBeLessThan(index.indexOf("## Machines"));
    expect(index).toContain("captures/machines-ordinateur.webp");
    expect(index).toContain("captures/machines-telephone.webp");
    expect(index).toContain("Route : `/machines`");
  });

  it("dit les pages sans capture et pourquoi", () => {
    expect(index).toContain("| `/machines/:id/proxmox` | absente des données |");
  });
});
