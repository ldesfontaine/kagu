package ping

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/ldesfontaine/kagu/internal/domain/heartbeat"
	"github.com/ldesfontaine/kagu/internal/kit/ratelimit"
)

// Ce que les pings attendent du composant heartbeat : recevoir un ping.
type HeartbeatReceiver interface {
	Receive(ctx context.Context, token string, ping heartbeat.Ping) (heartbeat.Heartbeat, error)
	// IsKnownToken dit si ce jeton ouvre un moniteur, sans rien écrire.
	IsKnownToken(ctx context.Context, token string) (bool, error)
}

type Options struct {
	Logger     *slog.Logger
	Heartbeats HeartbeatReceiver
	// ClientAddress rend l'adresse du client telle que le serveur la résout,
	// mandataires de confiance compris : la règle vit à la racine.
	ClientAddress func(r *http.Request) string
	// GlobalPerMinute borne les pings de toutes les sources ensemble ; 0 vaut
	// DefaultGlobalPerMinute.
	GlobalPerMinute int
	// Clock remplace l'horloge du limiteur, pour les tests ; nil = time.Now.
	Clock func() time.Time
}

type Handler struct {
	logger        *slog.Logger
	heartbeats    HeartbeatReceiver
	clientAddress func(r *http.Request) string
	sourceLimit   *ratelimit.BySource
	tokenLimit    *ratelimit.Limiter
}

func New(opts Options) *Handler {
	globalPerMinute := cmp.Or(opts.GlobalPerMinute, DefaultGlobalPerMinute)
	handler := &Handler{
		logger:        opts.Logger,
		heartbeats:    opts.Heartbeats,
		clientAddress: opts.ClientAddress,
		sourceLimit: ratelimit.NewBySourceWithGlobal(
			pingPerSourceRate, pingPerSourceBurst, pingIdle, ratelimit.GlobalLimit{PerMinute: globalPerMinute},
		),
		tokenLimit: ratelimit.NewCapped(pingPerTokenRate, pingPerTokenBurst, pingIdle, maxPingTokenBuckets),
	}
	if opts.Clock != nil {
		handler.sourceLimit.SetClock(opts.Clock)
		handler.tokenLimit.SetClock(opts.Clock)
	}
	return handler
}

// Routes déclare les routes des pings. Le serveur les monte à leur place
// dans son arbre, que server/routes_test.go fige.
func (h *Handler) Routes(add func(method, pattern string, handler http.HandlerFunc)) {
	add("GET", "/ping/{token}", h.finish)
	add("POST", "/ping/{token}", h.finish)
	add("GET", "/ping/{token}/start", h.start)
	add("POST", "/ping/{token}/start", h.start)
	add("GET", "/ping/{token}/{code}", h.exitCode)
	add("POST", "/ping/{token}/{code}", h.exitCode)
}
