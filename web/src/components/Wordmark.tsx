import { productName } from "../lib/product";

// Le nom du produit en mot-symbole. Il vient de la page (la balise que le
// serveur remplit), jamais d'un littéral : renommer le produit ne touche pas
// l'écran. Partagé par l'administration et la page de statut publique.
export function Wordmark() {
  return <span className="wordmark">{productName()}</span>;
}
