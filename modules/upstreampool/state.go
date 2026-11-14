package upstreampool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

var poolRuntimes = caddy.NewUsagePool()
var errStorage = errors.New("pool storage unavailable; observe state before retrying")

type runtimeKey struct{ namespace, pool string }

type storedState struct {
	Version   int    `json:"version"`
	Bootstrap string `json:"bootstrap_sha256"`
	Applied   Spec   `json:"applied"`
}

type stateStore struct {
	storage certmagic.Storage
	key     string
	logger  *zap.Logger
}

func specFingerprint(spec Spec) string {
	b, _ := json.Marshal(spec)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func decodeState(data []byte, bootstrap string) (storedState, error) {
	var state storedState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return state, errStorage
	}
	if decoder.Decode(new(any)) != io.EOF || state.Version != 1 || state.Bootstrap != bootstrap || validateSpec(state.Applied) != nil {
		return state, errStorage
	}
	return state, nil
}

func restorePool(ctx context.Context, storage certmagic.Storage, namespace, name string, bootstrap Spec, logger *zap.Logger) (*pool, error) {
	p := newPool(bootstrap)
	p.bootstrap = specFingerprint(bootstrap)
	scopeHash := sha256.Sum256([]byte(namespace))
	nameHash := sha256.Sum256([]byte(name))
	p.state = &stateStore{storage: storage, key: fmt.Sprintf("trueops_pools/%x/%x.json", scopeHash, nameHash), logger: logger}
	b, err := storage.Load(ctx, p.state.key)
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, errStorage
	}
	state, err := decodeState(b, p.bootstrap)
	if err != nil || state.Applied.Revision <= bootstrap.Revision {
		return nil, errStorage
	}
	p.current = &generation{spec: state.Applied}
	p.last = Update{ExpectedRevision: state.Applied.Revision - 1, Spec: state.Applied}
	return p, nil
}

func sameSpec(a, b Spec) bool { return a.Revision == b.Revision && slices.Equal(a.Targets, b.Targets) }

func (s *stateStore) save(ctx context.Context, bootstrap string, previous, next Spec) error {
	if err := s.storage.Lock(ctx, s.key+".lock"); err != nil {
		return errStorage
	}
	defer func() {
		if err := s.storage.Unlock(context.WithoutCancel(ctx), s.key+".lock"); err != nil && s.logger != nil {
			s.logger.Error("pool storage unlock failed")
		}
	}()
	b, err := s.storage.Load(ctx, s.key)
	if err == nil {
		state, decodeErr := decodeState(b, bootstrap)
		if decodeErr != nil {
			return decodeErr
		}
		// A previous uncertain Store may already have committed this exact plan.
		if sameSpec(state.Applied, next) {
			return nil
		}
		if !sameSpec(state.Applied, previous) {
			return errConflict
		}
	} else if !errors.Is(err, fs.ErrNotExist) || specFingerprint(previous) != bootstrap {
		return errStorage
	}
	state := storedState{Version: 1, Bootstrap: bootstrap, Applied: next}
	b, err = json.Marshal(state)
	if err != nil {
		return errStorage
	}
	if err = s.storage.Store(ctx, s.key, b); err != nil {
		return errStorage
	}
	return nil
}
