package agent

import (
	"errors"
	"io/fs"
	"os"

	"github.com/ldesfontaine/kagu/internal/fact/agentpolicy"
)

// « agent policy migrate » : sur une machine installée avant la politique,
// recopie dans la politique ce qu'identity.json porte (la machine, les droits,
// les ancres, la clé du serveur épinglée), à l'identique, puis l'efface
// d'identity.json. Il crée le dossier de la politique (root, 0755) : c'est à
// lui que l'agent reconnaît une machine qui ne relit plus jamais
// identity.json (R-A3-16). Sur un dossier qui existe déjà, rien ne se
// recopie : observe seul, comme l'agent l'applique.

// MigratePolicy écrit la première politique, après confirm. Sur une machine
// d'avant la politique, la question vient avant la création du dossier : un
// refus laisse la machine telle quelle. Une politique déjà là ne change pas ;
// ce qu'identity.json en garde encore (une migration interrompue) s'efface
// quand même.
func MigratePolicy(opts PolicyOptions, confirm func(PolicyChange) error) (PolicyChange, error) {
	identity, err := policyWriterIdentity(opts)
	if err != nil {
		return PolicyChange{}, err
	}
	if _, err := os.Lstat(opts.Place.Dir); errors.Is(err, fs.ErrNotExist) {
		copied := agentpolicy.Migrate(identity.legacy())
		asked := PolicyChange{First: true, Before: agentpolicy.Document{MachineID: identity.MachineID}, After: copied}
		asked.Added, asked.Removed = agentpolicy.Changes(asked.Before.Rights, asked.After.Rights)
		if err := confirm(asked); err != nil {
			return PolicyChange{}, err
		}
		alreadyConfirmed := func(PolicyChange) error { return nil }
		return writeFirstPolicy(opts, identity, &copied, alreadyConfirmed)
	}
	return writeFirstPolicy(opts, identity, nil, confirm)
}

// writeFirstPolicy écrit, verrou pris et après confirm, la première
// politique : copied, ou, dans un dossier qui existait, observe seul. Une
// politique trouvée sous le verrou ne se réécrit pas.
func writeFirstPolicy(opts PolicyOptions, identity Identity, copied *agentpolicy.Document, confirm func(PolicyChange) error) (PolicyChange, error) {
	dir, err := openPolicyDir(opts.Place)
	if err != nil {
		return PolicyChange{}, err
	}
	defer dir.Close()
	unlock, err := lockFile(dir, policyLockFile, nil)
	if err != nil {
		return PolicyChange{}, err
	}
	defer unlock()
	current, first, err := currentDocument(dir, opts.Place, identity)
	if err != nil {
		return PolicyChange{}, err
	}
	change := PolicyChange{Before: current, After: current}
	if first {
		change = PolicyChange{First: true, Before: agentpolicy.Document{MachineID: identity.MachineID}, After: current}
		if copied != nil {
			change.After = *copied
		}
		if change, err = writePolicy(opts, dir, "migrate", change, confirm); err != nil {
			return PolicyChange{}, err
		}
	}
	return change, forgetMigratedFields(opts)
}

// forgetMigratedFields efface d'identity.json ce que la politique porte
// désormais : les droits, les ancres et la clé du serveur. Le fichier reste
// au compte de l'agent.
func forgetMigratedFields(opts PolicyOptions) error {
	owner, err := stateOwner(opts.StateDir)
	if err != nil {
		return err
	}
	_, err = UpdateIdentity(opts.StateDir, &owner, func(identity *Identity) error {
		identity.Rights, identity.Anchors, identity.ServerKey = nil, nil, nil
		return nil
	})
	return err
}
