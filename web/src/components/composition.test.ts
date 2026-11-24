/// <reference types="node" />
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

// « Un composant, une fois » (décision P27) : ces tests lisent les sources.
// Chaque plafond est le compte d'aujourd'hui : il ne fait que descendre. Le
// test échoue s'il monte, et aussi s'il baisse sans que le plafond suive.

const sourceRoot = join(import.meta.dirname, "..");

type Source = { path: string; text: string };

// Les sources du front, tests exclus ; le chemin est relatif à src/.
function readSources(): Source[] {
  const found: Source[] = [];
  const walk = (directory: string) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(path);
      } else if (/\.(ts|tsx)$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name)) {
        found.push({ path: relative(sourceRoot, path).split("\\").join("/"), text: readFileSync(path, "utf8") });
      }
    }
  };
  walk(sourceRoot);
  return found;
}

const sources = readSources();

function countMatches(text: string, pattern: RegExp): number {
  return text.match(pattern)?.length ?? 0;
}

// countsPerFile : le nombre d'occurrences du motif, par fichier qui en a.
function countsPerFile(files: Source[], pattern: RegExp): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const file of files) {
    const count = countMatches(file.text, pattern);
    if (count > 0) counts[file.path] = count;
  }
  return counts;
}

// ceilingProblems compare les comptes aux plafonds : un fichier qui monte ou
// qui apparaît est refusé ; un fichier qui baisse oblige à baisser son plafond.
function ceilingProblems(counts: Record<string, number>, ceilings: Record<string, number>): string[] {
  const problems: string[] = [];
  for (const path of new Set([...Object.keys(counts), ...Object.keys(ceilings)])) {
    const found = counts[path] ?? 0;
    const ceiling = ceilings[path] ?? 0;
    if (found > ceiling) problems.push(`${path} : ${found} (plafond ${ceiling})`);
    if (found < ceiling) problems.push(`${path} : ${found}, le plafond est encore ${ceiling} : le baisser à ${found}`);
  }
  return problems.sort();
}

// listProblems compare une liste du jour à une liste admise : un nom de plus
// est refusé ; un nom admis qui a disparu oblige à le retirer.
function listProblems(found: string[], admitted: string[]): string[] {
  return [
    ...found.filter((name) => !admitted.includes(name)).map((name) => `${name} : absent de la liste admise`),
    ...admitted.filter((name) => !found.includes(name)).map((name) => `${name} : n'est plus absent, le retirer de la liste`),
  ].sort();
}

const pageSources = sources.filter((file) => file.path.startsWith("pages/") || file.path.startsWith("statut/"));

// Les balises de base d'une page : un composant les porte, la page ne les écrit pas.
const bareTags = /<(button|table|input|select|textarea)\b|role="dialog"/g;

const bareTagCeilings: Record<string, number> = {
  "pages/Audit.tsx": 1,
  "pages/VisualSystem.tsx": 7,
  "pages/alerts/AlertRow.tsx": 1,
  "pages/alerts/SelectableAlerts.tsx": 1,
  "pages/firewalls/FirewallFlows.tsx": 1,
  "pages/firewalls/FirewallInterfaces.tsx": 1,
  "pages/settings/ReachChoices.tsx": 1,
  "pages/settings/VerbChoices.tsx": 1,
};

// Le seul style en ligne : la position d'une infobulle, qui vient de la souris.
const inlineStyleHomes = ["components/netmap/LinkLayer.tsx"];

// Tout appel d'API passe par api/client.ts ; la page de statut publique est à part, exprès.
const fetchHomes = ["api/client.ts", "statut/"];

// Un ton s'écrit une fois, dans lib/.
const toneTables = /Record<[^;=]*,\s*Tone>/g;

const toneTableCeilings: Record<string, number> = {
  "components/ActionsCard.tsx": 1,
  "components/AgentAnchors.tsx": 1,
  "components/MachineSSHKeys.tsx": 1,
  "components/MachineStorage.tsx": 1,
  "components/PlanView.tsx": 1,
  "pages/backups/DatabaseSetup.tsx": 1,
  "pages/backups/Restore.tsx": 1,
  "pages/backups/Targets.tsx": 2,
  "pages/settings/AIAgentSection.tsx": 1,
  "pages/settings/MutesBlock.tsx": 1,
};

// Un composant exporté se montre dans la page vitrine. La liste nommée est ce
// qui n'y est pas encore : elle ne fait que raccourcir (un nom de plus est
// refusé ; un nom revenu dans la vitrine doit en sortir).
const showcasePath = "pages/VisualSystem.tsx";
const componentExport = /^export (?:default )?(?:function|const|class) ([A-Z][A-Za-z0-9]*)/gm;
const absentFromShowcase: string[] = [
  "components/ActionsCard.tsx : ActionsCard",
  "components/AgentAnchors.tsx : AgentAnchors",
  "components/AgentGate.tsx : AgentGate",
  "components/AgentUpdate.tsx : AgentUpdate",
  "components/AnchorFix.tsx : AnchorFix",
  "components/Card.tsx : EmptyCard",
  "components/Card.tsx : Note",
  "components/CategoryPill.tsx : CategoryPill",
  "components/Certificate.tsx : CertificateList",
  "components/Certificate.tsx : CertificatePill",
  "components/Certificate.tsx : Remaining",
  "components/Certificate.tsx : TrustPill",
  "components/CertificateCheck.tsx : AddressCheck",
  "components/CertificateCheck.tsx : CertificateFingerprint",
  "components/Chart.tsx : Chart",
  "components/Checklist.tsx : Checklist",
  "components/Choice.tsx : Choice",
  "components/ConfirmModal.tsx : ConfirmDialog",
  "components/ContainerTable.tsx : ContainerFilter",
  "components/ContainerTable.tsx : ContainerTable",
  "components/Copy.tsx : CopyButton",
  "components/Copy.tsx : CopyList",
  "components/Copy.tsx : TokenBox",
  "components/DeclaredServiceTable.tsx : DeclaredServiceTable",
  "components/DeleteMachineDialog.tsx : DeleteMachineDialog",
  "components/DeletePlanDialog.tsx : DeletePlanDialog",
  "components/DeletePlanDialog.tsx : PlanBody",
  "components/DeployCard.tsx : DeployCard",
  "components/DirectoryCard.tsx : DirectoryCard",
  "components/DirectoryTab.tsx : DirectoryTab",
  "components/Disclosure.tsx : Disclosure",
  "components/Disclosure.tsx : Fold",
  "components/Disclosure.tsx : FoldSection",
  "components/Disclosure.tsx : SettingsFold",
  "components/ExternalLink.tsx : ExternalLink",
  "components/Failure.tsx : Failure",
  "components/Field.tsx : Textarea",
  "components/FieldTip.tsx : FieldTip",
  "components/FileExplorer.tsx : FileExplorer",
  "components/FormBody.tsx : FormActions",
  "components/FormBody.tsx : FormBody",
  "components/GapPill.tsx : GapPill",
  "components/Icon.tsx : Mark",
  "components/ImageName.tsx : ImageName",
  "components/Inspector.tsx : Inspector",
  "components/InstallSteps.tsx : InstallSteps",
  "components/Layout.tsx : Brand",
  "components/Layout.tsx : Layout",
  "components/Loaded.tsx : Loaded",
  "components/LogViewer.tsx : LogViewer",
  "components/MachineHead.tsx : MachineHead",
  "components/MachineHead.tsx : Tabs",
  "components/MachineHypervisor.tsx : MachineHypervisor",
  "components/MachineIdentity.tsx : MachineIdentity",
  "components/MachineKind.tsx : MachineKind",
  "components/MachineSSHKeys.tsx : MachineSSHKeys",
  "components/MachineSelect.tsx : MachineSelect",
  "components/MachineStorage.tsx : MachineStorage",
  "components/MachineSystemdUnits.tsx : MachineSystemdUnits",
  "components/MachineThresholds.tsx : MachineThresholds",
  "components/MachineTodoCard.tsx : MachineTodoCard",
  "components/Matrix.tsx : Matrix",
  "components/MissingRight.tsx : MissingRight",
  "components/ModalForm.tsx : ModalForm",
  "components/NetworkGraph.tsx : NetworkGraph",
  "components/NetworkInspector.tsx : NetworkInspector",
  "components/NetworkView.tsx : NetworkView",
  "components/ObjectPicker.tsx : ObjectPicker",
  "components/PickList.tsx : PickList",
  "components/Pill.tsx : ContainerPill",
  "components/Pill.tsx : JobPill",
  "components/Pill.tsx : MachineStatePill",
  "components/Pill.tsx : ProbePill",
  "components/PlanView.tsx : PlanView",
  "components/ProbeTable.tsx : ProbeTable",
  "components/ProjectsTab.tsx : ProjectsTab",
  "components/PublicUrlNote.tsx : PublicUrlNote",
  "components/Resources.tsx : DiskVolumes",
  "components/Resources.tsx : MachineMeters",
  "components/Resources.tsx : ResourceHistory",
  "components/Resources.tsx : ResourceStats",
  "components/Rich.tsx : Rich",
  "components/RightsFields.tsx : RightsFields",
  "components/RoleCard.tsx : RoleCard",
  "components/RunStrip.tsx : RunStrip",
  "components/Select.tsx : EnumSelect",
  "components/ServiceLinks.tsx : ServiceLinks",
  "components/ServiceUpdateNote.tsx : ServiceUpdateNote",
  "components/ServicesTabs.tsx : ServicesTabs",
  "components/SettingRow.tsx : SettingBlock",
  "components/SupportBlock.tsx : SupportBlock",
  "components/SupportBlock.tsx : SupportDetails",
  "components/SupportBlock.tsx : SupportLine",
  "components/TabNav.tsx : TabNav",
  "components/Table.tsx : Subject",
  "components/ThresholdForm.tsx : ThresholdForm",
  "components/TodoCard.tsx : TodoCard",
  "components/UpdateCard.tsx : UpdateCard",
  "components/UptimeBar.tsx : UptimeBar",
  "components/VerbRequestsCard.tsx : VerbRequestsCard",
  "components/Verdict.tsx : Verdict",
  "components/Wizard.tsx : WizardBar",
  "components/Wordmark.tsx : Wordmark",
  "components/netmap/EmptyZones.tsx : EmptyZones",
  "components/netmap/FirewallBox.tsx : FirewallBox",
  "components/netmap/InternetRegion.tsx : InternetRegion",
  "components/netmap/LinkLayer.tsx : LinkLayer",
  "components/netmap/LinkList.tsx : LinkList",
  "components/netmap/MachineBox.tsx : MachineBox",
  "components/netmap/NetworkMap.tsx : NetworkMap",
  "components/netmap/ServiceChip.tsx : ServiceChip",
  "components/netmap/ZoneLane.tsx : ZoneLane",
];

function componentsAbsentFromShowcase(files: Source[], showcase: string): string[] {
  const absent: string[] = [];
  for (const file of files.filter((candidate) => candidate.path.startsWith("components/") && candidate.path.endsWith(".tsx"))) {
    for (const match of file.text.matchAll(componentExport)) {
      const name = match[1]!;
      if (!new RegExp(`\\b${name}\\b`).test(showcase)) absent.push(`${file.path} : ${name}`);
    }
  }
  return absent.sort();
}

// Ce que le serveur sait, le front ne le recalcule pas : les clés de refus
// `*_right_missing` et leur table vers un droit (le refus porte son fix), et
// les listes d'images de bases.
const serverRules = /_right_missing|refusalRights|\(\s*postgres\w*\|[^)]*\)|\[\s*"postgres\w*"\s*,/g;

const serverRuleCeilings: Record<string, number> = {
  "lib/alerts.ts": 1,
  "lib/backupOverview.ts": 4,
  "lib/containers.ts": 1,
  // machine.fit_right_missing : une clé du catalogue, pas un refus.
  "lib/rights.ts": 1,
};

describe("composition", () => {
  it("sees the sources it guards", () => {
    expect(pageSources.length).toBeGreaterThan(10);
    expect(sources.some((file) => file.path === showcasePath)).toBe(true);
    expect(sources.some((file) => file.path.startsWith("statut/"))).toBe(true);
  });

  it("keeps bare tags out of the pages", () => {
    expect(ceilingProblems(countsPerFile(pageSources, bareTags), bareTagCeilings)).toEqual([]);
  });

  it("keeps inline styles to their one home", () => {
    const outside = sources.filter((file) => !inlineStyleHomes.includes(file.path));
    expect(Object.keys(countsPerFile(outside, /style=\{\{/g))).toEqual([]);
    const home = sources.filter((file) => inlineStyleHomes.includes(file.path));
    expect(Object.keys(countsPerFile(home, /style=\{\{/g))).toEqual(inlineStyleHomes);
  });

  it("calls the API through api/client.ts only", () => {
    const outside = sources.filter((file) => !fetchHomes.some((home) => file.path.startsWith(home)));
    expect(Object.keys(countsPerFile(outside, /(?<![.\w])fetch\(/g))).toEqual([]);
    expect(Object.keys(countsPerFile(sources, /(?<![.\w])fetch\(/g)).sort()).toEqual(["api/client.ts", "statut/StatusPage.tsx"]);
  });

  it("writes a tone table once, in lib/", () => {
    const outside = sources.filter((file) => !file.path.startsWith("lib/"));
    expect(ceilingProblems(countsPerFile(outside, toneTables), toneTableCeilings)).toEqual([]);
    expect(Object.keys(countsPerFile(sources.filter((file) => file.path.startsWith("lib/")), toneTables)).length).toBeGreaterThan(0);
  });

  it("shows every component in the showcase", () => {
    const showcase = sources.find((file) => file.path === showcasePath)!.text;
    const absent = componentsAbsentFromShowcase(sources, showcase);
    expect(listProblems(absent, absentFromShowcase)).toEqual([]);
  });

  it("leaves the server's rules to the server", () => {
    const library = sources.filter((file) => file.path.startsWith("lib/"));
    expect(ceilingProblems(countsPerFile(library, serverRules), serverRuleCeilings)).toEqual([]);
  });

  it("catches each fault it guards", () => {
    const faulty = (path: string, text: string): Source[] => [{ path, text }];
    expect(countsPerFile(faulty("pages/X.tsx", "<button>"), bareTags)).toEqual({ "pages/X.tsx": 1 });
    expect(countsPerFile(faulty("pages/X.tsx", '<div role="dialog">'), bareTags)).toEqual({ "pages/X.tsx": 1 });
    expect(countsPerFile(faulty("pages/X.tsx", "<div style={{ left: 1 }}>"), /style=\{\{/g)).toEqual({ "pages/X.tsx": 1 });
    expect(countsPerFile(faulty("pages/X.tsx", "await fetch(url)"), /(?<![.\w])fetch\(/g)).toEqual({ "pages/X.tsx": 1 });
    expect(countsPerFile(faulty("pages/X.tsx", "const t: Record<State, Tone> = {}"), toneTables)).toEqual({ "pages/X.tsx": 1 });
    expect(countsPerFile(faulty("lib/x.ts", '"backup.source_right_missing"'), serverRules)).toEqual({ "lib/x.ts": 1 });
    expect(countsPerFile(faulty("lib/x.ts", "const refusalRights = {}"), serverRules)).toEqual({ "lib/x.ts": 1 });
    expect(countsPerFile(faulty("lib/x.ts", "/^(postgres|mariadb)$/"), serverRules)).toEqual({ "lib/x.ts": 1 });
    expect(componentsAbsentFromShowcase(faulty("components/Y.tsx", "export function Y() {}"), "<Z />")).toEqual(["components/Y.tsx : Y"]);
    expect(ceilingProblems({ "a.tsx": 2 }, { "a.tsx": 1 })).toHaveLength(1);
    expect(ceilingProblems({ "a.tsx": 1 }, { "a.tsx": 2 })).toHaveLength(1);
    expect(ceilingProblems({ "b.tsx": 1 }, {})).toHaveLength(1);
    expect(listProblems(["a : B"], [])).toHaveLength(1);
    expect(listProblems([], ["a : B"])).toHaveLength(1);
    expect(listProblems(["a : C"], ["a : B"])).toHaveLength(2);
  });
});
