package agentpolicy

import (
	"slices"
	"testing"
)

// Le détail d'une carte de jeu : les droits que le jeu pose partout, dans
// les groupes de l'onglet Droits et dans leur ordre, chaque droit une fois.
func TestSetGroups_AreTheSetRightsInTheRightsTabOrder(t *testing.T) {
	for _, set := range Sets() {
		var listed []string
		previous := -1
		for _, grouped := range set.Groups() {
			position := slices.Index(groups, grouped.Group)
			if position <= previous {
				t.Errorf("%s: group %s out of order", set, grouped.Group)
			}
			previous = position
			listed = append(listed, grouped.Rights...)
		}
		var want []string
		for _, right := range set.Rights(SetHost{ServicesRoot: "/srv/workspace"}) {
			want = append(want, right.Name)
		}
		slices.Sort(listed)
		slices.Sort(want)
		if !slices.Equal(listed, want) {
			t.Errorf("%s: grouped %v, the set lays %v", set, listed, want)
		}
	}
}
