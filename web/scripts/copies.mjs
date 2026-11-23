// Les copies du front (décision P27). Le plafond est le compte d'aujourd'hui :
// il ne fait que descendre. Le script échoue s'il monte, et aussi s'il baisse
// sans que le plafond suive.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ceiling = 8;

const reportDirectory = mkdtempSync(join(tmpdir(), "copies-"));
try {
  execFileSync(
    "npx",
    ["--no-install", "jscpd", "src", "--min-tokens", "60", "--ignore", "**/*.test.*", "--reporters", "json", "--output", reportDirectory, "--silent"],
    { stdio: "inherit" },
  );
  const report = JSON.parse(readFileSync(join(reportDirectory, "jscpd-report.json"), "utf8"));
  const found = report.statistics.total.clones;
  if (found > ceiling) {
    console.error(`copies : ${found} copies de 60 jetons et plus, le plafond est ${ceiling}`);
    process.exit(1);
  }
  if (found < ceiling) {
    console.error(`copies : ${found} copies restent, le plafond est encore ${ceiling} : le baisser à ${found}`);
    process.exit(1);
  }
  console.log(`copies : ${found} (plafond ${ceiling})`);
} finally {
  rmSync(reportDirectory, { recursive: true, force: true });
}
