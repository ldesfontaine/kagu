# openCloud — build, run, test, ci. Les outils sont épinglés par version ici
# et nulle part ailleurs ; la CI appelle ces mêmes cibles.

MODULE      := github.com/ldesfontaine/kagu
VERSION     ?= v0.0.1
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS     := -s -w -X $(MODULE)/internal/kit/version.number=$(VERSION) -X $(MODULE)/internal/kit/version.commit=$(COMMIT)

STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOIMPORTS   := golang.org/x/tools/cmd/goimports@v0.50.0
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0
GOSEC       := github.com/securego/gosec/v2/cmd/gosec@v2.29.0
DUPL        := github.com/mibk/dupl@v1.1.0

FRONT_DIR   := web

export CGO_ENABLED = 0

.PHONY: build release release-binaries run test ci fmt vet staticcheck vulncheck gosec dupl front front-check e2e clean

# Le front compilé est embarqué par go:embed : il précède tout build ou test Go.
build: front
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/opencloud ./cmd/kagu

# Les binaires publiés : amd64 et arm64, statiques, avec leurs sommes. Le tag
# release refuse de compiler sans clé de secours (internal/kit/release/key_release.go).
release: front
	$(MAKE) release-binaries

# Sans npm, sur le web/dist déjà là : le job rebuild de la CI recompile ainsi,
# depuis le paquet du front que le job de construction publie. -buildvcs=false :
# le commit passe par ldflags, les octets ne dépendent pas de l'état du clone.
RELEASE_DIR ?= dist-release
release-binaries:
	rm -rf $(RELEASE_DIR) && mkdir -p $(RELEASE_DIR)
	GOARCH=amd64 go build -tags release -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o $(RELEASE_DIR)/opencloud-linux-amd64 ./cmd/kagu
	GOARCH=arm64 go build -tags release -buildvcs=false -trimpath -ldflags '$(LDFLAGS)' -o $(RELEASE_DIR)/opencloud-linux-arm64 ./cmd/kagu
	cd $(RELEASE_DIR) && sha256sum opencloud-linux-* > SHA256SUMS

# npm ci ne rejoue que si le verrou a changé ; le premier verrou se produit
# avec npx npm@10 install si le npm de la machine (9.x) plante.
$(FRONT_DIR)/node_modules/.stamp: $(FRONT_DIR)/package-lock.json
	cd $(FRONT_DIR) && npm ci && touch node_modules/.stamp

front: $(FRONT_DIR)/node_modules/.stamp
	find $(FRONT_DIR)/dist -mindepth 1 -not -name .gitkeep -delete
	cd $(FRONT_DIR) && npm run build

# L'audit précède les tests : une dépendance de production vulnérable arrête
# tout. `audit=false` du .npmrc ne coupe que l'audit de npm ci ; l'appel
# explicite interroge le registre (il faut donc le réseau).
front-check: $(FRONT_DIR)/node_modules/.stamp
	cd $(FRONT_DIR) && npm audit --omit=dev --audit-level=high
	cd $(FRONT_DIR) && npm run check

# Le parcours navigateur : Chromium sans tête contre le vrai serveur sur des
# données fictives (le test Go TestE2EFixtureServer, compilé à part pour que
# Playwright l'arrête proprement). `playwright install` ne télécharge que si
# le navigateur manque.
e2e: front $(FRONT_DIR)/node_modules/.stamp
	go test -c -o $(FRONT_DIR)/e2e/.fixture.test ./internal/edge/server
	cd $(FRONT_DIR) && npx playwright install chromium && npm run e2e

# dev/ est ton /etc et ton /var/lib locaux : créé une fois, jamais effacé.
# serve crée dev/state lui-même, en 0700 : ouvert, il refuse de démarrer.
run: build
	@mkdir -p dev
	@test -f dev/config.toml || printf 'listen = "127.0.0.1:8080"\nstate_dir = "%s/dev/state"\n' "$(CURDIR)" > dev/config.toml
	./bin/opencloud serve -config dev/config.toml

test: front
	go test ./...

ci: fmt vet staticcheck front-check e2e test vulncheck gosec dupl build

fmt:
	@unformatted="$$(gofmt -l . ; go run $(GOIMPORTS) -l .)"; \
	if [ -n "$$unformatted" ]; then echo "à formater :"; echo "$$unformatted"; exit 1; fi

# vet et staticcheck compilent web/ : l'embed exige dist/ rempli.
vet: front
	go vet ./...

staticcheck: front
	go run $(STATICCHECK) ./...

vulncheck:
	go run $(GOVULNCHECK) ./...

gosec:
	go run $(GOSEC) -quiet ./...

# Les copies Go de 80 jetons et plus, par fichier, comparées à la liste des
# copies admises (scripts/dupl-admises.txt) : elle ne fait que raccourcir.
dupl:
	go run $(DUPL) -t 80 -plumbing internal cmd | scripts/dupl-releve.sh

clean:
	rm -rf bin/opencloud dist dist-release
	find $(FRONT_DIR)/dist -mindepth 1 -not -name .gitkeep -delete
