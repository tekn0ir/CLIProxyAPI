package auth

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func soonestResetAuth(id string, resetAt time.Time) *Auth {
	auth := &Auth{ID: id, Provider: "claude"}
	if !resetAt.IsZero() {
		auth.Quota.Signals = map[string]string{claudeWeeklyResetSignal: strconv.FormatInt(resetAt.Unix(), 10)}
	}
	return auth
}

func fixedNowSoonestResetSelector(now time.Time) *SoonestResetSelector {
	return &SoonestResetSelector{nowFunc: func() time.Time { return now }}
}

func pickIDs(t *testing.T, selector Selector, auths []*Auth, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for range n {
		got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick() error = %v", err)
		}
		ids = append(ids, got.ID)
	}
	return ids
}

func TestSoonestResetSelectorPicksEarliestWeeklyReset(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	selector := fixedNowSoonestResetSelector(now)
	auths := []*Auth{
		soonestResetAuth("a-four-days", now.Add(96*time.Hour)),
		soonestResetAuth("b-tomorrow", now.Add(24*time.Hour)),
		soonestResetAuth("c-unknown", time.Time{}),
	}
	for i, id := range pickIDs(t, selector, auths, 3) {
		if id != "b-tomorrow" {
			t.Fatalf("pick %d = %q, want b-tomorrow every time", i, id)
		}
	}
}

func TestSoonestResetSelectorTreatsPastResetAsUnknown(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	selector := fixedNowSoonestResetSelector(now)
	auths := []*Auth{
		soonestResetAuth("a-rolled-over", now.Add(-time.Minute)),
		soonestResetAuth("b-in-three-days", now.Add(72*time.Hour)),
	}
	if got := pickIDs(t, selector, auths, 1)[0]; got != "b-in-three-days" {
		t.Fatalf("Pick() = %q, want b-in-three-days", got)
	}
}

func TestSoonestResetSelectorIgnoresMalformedReset(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	selector := fixedNowSoonestResetSelector(now)
	bad := &Auth{ID: "a-bad", Provider: "claude", Quota: QuotaState{Signals: map[string]string{claudeWeeklyResetSignal: "soon"}}}
	auths := []*Auth{bad, soonestResetAuth("b-known", now.Add(48*time.Hour))}
	if got := pickIDs(t, selector, auths, 1)[0]; got != "b-known" {
		t.Fatalf("Pick() = %q, want b-known", got)
	}
}

func TestSoonestResetSelectorRotatesTies(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	selector := fixedNowSoonestResetSelector(now)
	auths := []*Auth{
		soonestResetAuth("a", time.Time{}),
		soonestResetAuth("b", time.Time{}),
		soonestResetAuth("c", time.Time{}),
	}
	got := pickIDs(t, selector, auths, 4)
	want := []string{"a", "b", "c", "a"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("picks = %v, want %v", got, want)
		}
	}
}

func TestSoonestResetSelectorSkipsCooledDownCredential(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	selector := fixedNowSoonestResetSelector(now)
	model := "claude-fable-5-2"
	soonest := soonestResetAuth("a-soonest", now.Add(24*time.Hour))
	soonest.ModelStates = map[string]*ModelState{model: {
		Status:         StatusActive,
		Unavailable:    true,
		NextRetryAfter: now.Add(time.Hour),
		Quota:          QuotaState{Exceeded: true},
	}}
	later := soonestResetAuth("b-later", now.Add(72*time.Hour))
	got, err := selector.Pick(context.Background(), "claude", model, cliproxyexecutor.Options{}, []*Auth{soonest, later})
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got.ID != "b-later" {
		t.Fatalf("Pick() = %q, want b-later while a-soonest is cooling down", got.ID)
	}
}

func TestSoonestResetSelectorKeepsPriorityTiers(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	selector := fixedNowSoonestResetSelector(now)
	lowSoon := soonestResetAuth("a-low-soon", now.Add(time.Hour))
	lowSoon.Attributes = map[string]string{"priority": "0"}
	highLate := soonestResetAuth("b-high-late", now.Add(144*time.Hour))
	highLate.Attributes = map[string]string{"priority": "10"}
	if got := pickIDs(t, selector, []*Auth{lowSoon, highLate}, 1)[0]; got != "b-high-late" {
		t.Fatalf("Pick() = %q, want the higher priority tier first", got)
	}
}

func TestUnwrapSoonestResetSelector(t *testing.T) {
	t.Parallel()
	inner := &SoonestResetSelector{}
	if UnwrapSoonestResetSelector(inner) != inner {
		t.Fatal("bare selector not unwrapped")
	}
	wrapped := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: inner, TTL: time.Hour})
	defer wrapped.Stop()
	if UnwrapSoonestResetSelector(wrapped) != inner {
		t.Fatal("session affinity fallback not unwrapped")
	}
	if UnwrapSoonestResetSelector(&RoundRobinSelector{}) != nil {
		t.Fatal("unrelated selector unwrapped")
	}
}

// The manager routes non built-in selectors through the legacy pick path; check the
// strategy works end to end there, alone and behind session affinity.
func TestManagerPickNextUsesSoonestReset(t *testing.T) {
	for _, affinity := range []bool{false, true} {
		t.Run("affinity="+strconv.FormatBool(affinity), func(t *testing.T) {
			ctx := context.Background()
			var selector Selector = &SoonestResetSelector{}
			if affinity {
				wrapped := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: selector, TTL: time.Hour})
				t.Cleanup(wrapped.Stop)
				selector = wrapped
			}
			manager := NewManager(nil, selector, nil)
			manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "claude"})

			model := "soonest-reset-manager-model-" + strconv.FormatBool(affinity)
			now := time.Now()
			auths := []*Auth{
				soonestResetAuth("acct-a-four-days", now.Add(96*time.Hour)),
				soonestResetAuth("acct-b-tomorrow", now.Add(24*time.Hour)),
				soonestResetAuth("acct-c-unknown", time.Time{}),
			}
			ids := make([]string, 0, len(auths))
			for _, auth := range auths {
				if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
					t.Fatalf("register %s: %v", auth.ID, errRegister)
				}
				ids = append(ids, auth.ID)
			}
			registerSchedulerModels(t, "claude", model, ids...)

			for i := range 3 {
				picked, _, errPick := manager.pickNext(ctx, "claude", model, cliproxyexecutor.Options{}, nil)
				if errPick != nil {
					t.Fatalf("pick %d: %v", i, errPick)
				}
				if picked.ID != "acct-b-tomorrow" {
					t.Fatalf("pick %d = %q, want acct-b-tomorrow", i, picked.ID)
				}
			}

			manager.MarkResult(ctx, Result{
				AuthID:   "acct-b-tomorrow",
				Provider: "claude",
				Model:    model,
				Success:  false,
				Error:    &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota exceeded"},
			})
			picked, _, errPick := manager.pickNext(ctx, "claude", model, cliproxyexecutor.Options{}, nil)
			if errPick != nil {
				t.Fatalf("pick after cooldown: %v", errPick)
			}
			if picked.ID != "acct-a-four-days" {
				t.Fatalf("pick after cooldown = %q, want acct-a-four-days", picked.ID)
			}
		})
	}
}
