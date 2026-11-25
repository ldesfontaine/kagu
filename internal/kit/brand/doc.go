// Package brand est le seul endroit où le nom du produit s'écrit. Il ne
// dépend que de la bibliothèque standard et part de trois racines, seules
// écrites en littéral : ProductName (le nom affiché), ID (l'identifiant
// technique, d'où viennent les chemins, les unités et les étiquettes du
// protocole) et TokenPrefix (les jetons). Tout le reste se construit depuis
// elles (TestBrand_EveryNameDerivesFromID).
//
// Un test (TestProductNameIsNotALiteral) échoue si le nom ou l'un des
// préfixes de jeton réapparaît en littéral ailleurs dans le code Go ou les
// composants du front, et si l'ancien nom réapparaît où que ce soit hors de
// l'histoire (migrations, journaux de versions, documents de docs/projet) :
// pour l'écrire, on passe par ce paquet.
package brand
