package lock

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireAndRelease(t *testing.T) {
	dir := t.TempDir()

	l, err := Acquire(dir)
	if err != nil {
		t.Fatalf("first Acquire failed: %v", err)
	}
	if l == nil {
		t.Fatal("first Acquire returned nil lock")
	}
	t.Cleanup(func() { l.Release() })

	// The lock file should now exist and contain our PID.
	data, err := os.ReadFile(filepath.Join(dir, ".lock"))
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("pid file is empty after Acquire")
	}
}

func TestDoubleAcquireFails(t *testing.T) {
	dir := t.TempDir()

	l1, err := Acquire(dir)
	if err != nil {
		t.Fatalf("first Acquire failed: %v", err)
	}
	t.Cleanup(func() { l1.Release() })

	// A second Acquire on the same dir must fail because l1 still holds it.
	if _, err := Acquire(dir); err == nil {
		t.Fatal("second Acquire succeeded while first lock is held")
	}
}

func TestReleaseAllowsReacquire(t *testing.T) {
	dir := t.TempDir()

	l1, err := Acquire(dir)
	if err != nil {
		t.Fatalf("first Acquire failed: %v", err)
	}
	l1.Release()

	// After Release, a new Acquire must succeed.
	l2, err := Acquire(dir)
	if err != nil {
		t.Fatalf("reacquire after Release failed: %v", err)
	}
	l2.Release()
}

func TestStaleLockIsRemoved(t *testing.T) {
	dir := t.TempDir()

	// Write a stale lock pointing to a PID that is guaranteed not to exist.
	// PID 2147483647 is extremely unlikely to be in use.
	stalePath := filepath.Join(dir, ".lock")
	if err := os.WriteFile(stalePath, []byte("2147483647\n"), 0o600); err != nil {
		t.Fatalf("write stale pid file: %v", err)
	}

	l, err := Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire with stale lock failed: %v", err)
	}
	t.Cleanup(func() { l.Release() })
}

func TestAlive(t *testing.T) {
	// Our own process is definitely alive.
	if !alive(os.Getpid()) {
		t.Fatal("alive(self) returned false")
	}
	// A very large PID is almost certainly not alive.
	if alive(2147483647) {
		t.Fatal("alive(2147483647) returned true")
	}
}
