package upstreampool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

type faultStorage struct {
	certmagic.Storage
	fail, commitError bool
	entered, proceed  chan struct{}
}

func (s *faultStorage) Store(ctx context.Context, key string, value []byte) error {
	if s.entered != nil {
		close(s.entered)
		select {
		case <-s.proceed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s.fail {
		return errors.New("fixture storage failure")
	}
	if err := s.Storage.Store(ctx, key, value); err != nil {
		return err
	}
	if s.commitError {
		return errors.New("fixture uncertain store response")
	}
	return nil
}

func TestAppliedPoolSurvivesRestartAndFencesOldInstance(t *testing.T) {
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	boot := Spec{Revision: 1, Targets: []string{"127.0.0.1:12001"}}
	p, err := restorePool(t.Context(), storage, "gateway-a", "site", boot, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	u := Update{ExpectedInstance: p.instance, ExpectedRevision: 1, Spec: Spec{Revision: 2, Targets: []string{"127.0.0.1:12002"}}}
	if _, err = p.replace(t.Context(), p.instance, u); err != nil {
		t.Fatal(err)
	}
	restored, err := restorePool(t.Context(), storage, "gateway-a", "site", boot, zap.NewNop())
	if err != nil || !sameSpec(restored.current.spec, u.Spec) || restored.instance == p.instance {
		t.Fatalf("restart: %v %+v", err, restored)
	}
	if _, err = restored.replace(t.Context(), restored.instance, u); !errors.Is(err, errConflict) {
		t.Fatal("previous process instance accepted", err)
	}
	u.ExpectedInstance = restored.instance
	if _, err = restored.replace(t.Context(), restored.instance, u); err != nil {
		t.Fatal("exact durable duplicate", err)
	}
	other, err := restorePool(t.Context(), storage, "gateway-b", "site", boot, zap.NewNop())
	if err != nil || other.current.spec.Revision != 1 {
		t.Fatal("storage namespace leakage", err)
	}
	changed := Spec{Revision: 1, Targets: []string{"127.0.0.1:13000"}}
	if _, err = restorePool(t.Context(), storage, "gateway-a", "site", changed, zap.NewNop()); !errors.Is(err, errStorage) {
		t.Fatal("changed bootstrap silently replaced applied state", err)
	}
	t.Log("native file storage restored V2, rejected old process identity and isolated another namespace")
}

func TestStorageFailureAndUncertainResponsePreserveServingPool(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-store", true: "after-store"}[uncertain], func(t *testing.T) {
			storage := &faultStorage{Storage: &certmagic.FileStorage{Path: t.TempDir()}, fail: !uncertain, commitError: uncertain}
			p, err := restorePool(t.Context(), storage, "gateway", "site", Spec{Revision: 1, Targets: []string{"127.0.0.1:12001"}}, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			u := Update{ExpectedInstance: p.instance, ExpectedRevision: 1, Spec: Spec{Revision: 2, Targets: []string{"127.0.0.1:12002"}}}
			if _, err = p.replace(t.Context(), p.instance, u); !errors.Is(err, errStorage) || p.current.spec.Revision != 1 {
				t.Fatal("storage failure changed serving state", err)
			}
			storage.fail, storage.commitError = false, false
			if _, err = p.replace(t.Context(), p.instance, u); err != nil || p.current.spec.Revision != 2 {
				t.Fatal("explicit exact retry could not resolve outcome", err)
			}
			t.Log("storage error preserved V1; explicit identical retry confirmed V2 without a different plan")
		})
	}
}

func TestSlowDurabilityDoesNotBlockRequestAdmission(t *testing.T) {
	storage := &faultStorage{Storage: &certmagic.FileStorage{Path: t.TempDir()}, entered: make(chan struct{}), proceed: make(chan struct{})}
	p, err := restorePool(t.Context(), storage, "gateway", "site", Spec{Revision: 1, Targets: []string{"127.0.0.1:12001"}}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := p.replace(t.Context(), p.instance, Update{ExpectedInstance: p.instance, ExpectedRevision: 1, Spec: Spec{Revision: 2, Targets: []string{"127.0.0.1:12002"}}})
		done <- err
	}()
	<-storage.entered
	admitted := make(chan uint64, 1)
	go func() { g := p.acquire(); admitted <- g.spec.Revision; p.release(g) }()
	select {
	case revision := <-admitted:
		if revision != 1 {
			close(storage.proceed)
			<-done
			t.Fatal("uncommitted pool admitted")
		}
	case <-time.After(time.Second):
		close(storage.proceed)
		<-done
		t.Fatal("storage write blocked request admission")
	}
	close(storage.proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	t.Log("requests continued on V1 during blocked Store; V2 admitted only after durability")
}

func TestMissingOrCorruptCheckpointDoesNotResetAppliedPool(t *testing.T) {
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	boot := Spec{Revision: 1, Targets: []string{"127.0.0.1:12001"}}
	p, err := restorePool(t.Context(), storage, "gateway", "site", boot, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	u := Update{ExpectedInstance: p.instance, ExpectedRevision: 1, Spec: Spec{Revision: 2, Targets: []string{"127.0.0.1:12002"}}}
	if _, err = p.replace(t.Context(), p.instance, u); err != nil {
		t.Fatal(err)
	}
	if err = storage.Delete(t.Context(), p.state.key); err != nil {
		t.Fatal(err)
	}
	u.ExpectedRevision, u.Revision = 2, 3
	if _, err = p.replace(t.Context(), p.instance, u); !errors.Is(err, errStorage) || p.current.spec.Revision != 2 {
		t.Fatal("missing checkpoint recreated behind active pool", err)
	}
	if err = storage.Store(t.Context(), p.state.key, []byte(`{"version":1,"unknown":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, err = restorePool(t.Context(), storage, "gateway", "site", boot, zap.NewNop()); !errors.Is(err, errStorage) {
		t.Fatal("corrupt state reverted to bootstrap", err)
	}
}
