package auth

import (
	"context"
	"math"
	"strconv"
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// claudeWeeklyResetSignal is the canonical header key holding the Unix time at which a
// Claude credential's 7-day quota window resets, as captured by the passive quota observer.
const claudeWeeklyResetSignal = "Anthropic-Ratelimit-Unified-7d-Reset"

// SoonestResetSelector prefers the available credential whose weekly quota resets first.
//
// Quota left on a credential when its window resets is lost, so spending the credential that
// resets soonest first wastes the least. Credentials without a known future reset (never
// observed since start-up, a window that already rolled over, or providers that do not
// report one) sort after every credential with a known reset. Ties, including the group of
// unknown credentials, rotate round-robin.
type SoonestResetSelector struct {
	tieBreak RoundRobinSelector
	nowFunc  func() time.Time
}

// Pick selects the available auth with the earliest known weekly reset.
func (s *SoonestResetSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	now := time.Now()
	if s.nowFunc != nil {
		now = s.nowFunc()
	}
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)

	earliest := int64(math.MaxInt64)
	ties := make([]*Auth, 0, len(available))
	for _, candidate := range available {
		reset := weeklyResetUnix(candidate, now)
		switch {
		case reset < earliest:
			earliest = reset
			ties = append(ties[:0], candidate)
		case reset == earliest:
			ties = append(ties, candidate)
		}
	}
	if len(ties) == 1 {
		return ties[0], nil
	}
	// The tie group is a subset of already validated candidates, kept in their sorted order,
	// so the round-robin cursor advances exactly as it would over the full list.
	return s.tieBreak.Pick(context.WithValue(ctx, prevalidatedAuthCandidatesKey{}, true), provider, model, opts, ties)
}

// weeklyResetUnix returns the credential's next weekly reset as Unix seconds, or
// math.MaxInt64 when no future reset is known.
func weeklyResetUnix(auth *Auth, now time.Time) int64 {
	if auth == nil {
		return math.MaxInt64
	}
	raw := strings.TrimSpace(auth.Quota.Signals[claudeWeeklyResetSignal])
	if raw == "" {
		return math.MaxInt64
	}
	reset, errParse := strconv.ParseInt(raw, 10, 64)
	if errParse != nil || reset <= now.Unix() {
		return math.MaxInt64
	}
	return reset
}

// UnwrapSoonestResetSelector extracts the underlying *SoonestResetSelector from a bare
// selector or a SessionAffinitySelector wrapper, so config reloads keep the tie-break cursor.
func UnwrapSoonestResetSelector(selector Selector) *SoonestResetSelector {
	if soonest, ok := selector.(*SoonestResetSelector); ok {
		return soonest
	}
	if affinity, ok := selector.(*SessionAffinitySelector); ok && affinity != nil {
		if soonest, okFallback := affinity.fallback.(*SoonestResetSelector); okFallback {
			return soonest
		}
	}
	return nil
}
