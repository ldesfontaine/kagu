import type { ReactNode } from "react";

import { Brand } from "../components/Layout";
import "./AccessPage.scss";

// Le cadre des écrans d'accès : la marque, puis le contenu, sans barre
// latérale. narrow : la colonne étroite de la connexion.
export function AccessPage({ narrow = false, children }: { narrow?: boolean; children: ReactNode }) {
  return (
    <main className="access-page">
      <div className={narrow ? "access-column access-column-narrow" : "access-column"}>
        <Brand />
        {children}
      </div>
    </main>
  );
}
