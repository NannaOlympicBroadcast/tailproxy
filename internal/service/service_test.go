package service

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateAndTokenFiles(t *testing.T) {
	p := NewPaths(filepath.Join(t.TempDir(), "state"))
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(p.Dir); info.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", info.Mode().Perm())
	}
	if st, err := p.ReadState(); st != nil || err != nil {
		t.Fatalf("empty dir: %v %v", st, err)
	}
	want := State{PID: os.Getpid(), URL: "http://127.0.0.1:7708/", Config: "/etc/tp.yaml", TokenFile: p.Token, Started: time.Now().Round(time.Second)}
	if err := p.WriteState(want); err != nil {
		t.Fatal(err)
	}
	if err := p.SaveToken("tok-123"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p.State, p.Token} {
		if info, _ := os.Stat(f); info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, info.Mode().Perm())
		}
	}
	st, err := p.Running()
	if err != nil || st == nil || st.PID != want.PID || !st.Started.Equal(want.Started) {
		t.Fatalf("Running = %+v, %v", st, err)
	}
	if tok, err := p.ReadToken(); tok != "tok-123" || err != nil {
		t.Fatalf("ReadToken = %q, %v", tok, err)
	}
	// Cleanup by another pid must not remove a live instance's files.
	p.Cleanup(os.Getpid() + 1)
	if _, err := os.Stat(p.Token); err != nil {
		t.Fatal("cleanup by a different pid removed a live instance's token")
	}
	p.Cleanup(os.Getpid())
	for _, f := range []string{p.State, p.Token} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("%s not removed", f)
		}
	}
}

func TestStaleStateIsCleanedUp(t *testing.T) {
	p := NewPaths(t.TempDir())
	// PID of a process that has exited.
	proc, err := os.StartProcess("/bin/true", []string{"true"}, &os.ProcAttr{})
	if err != nil {
		t.Skip("cannot start /bin/true:", err)
	}
	proc.Wait()
	p.WriteState(State{PID: proc.Pid})
	p.SaveToken("stale")
	if st, err := p.Running(); st != nil || err != nil {
		t.Fatalf("Running = %+v, %v; want nil for a dead pid", st, err)
	}
	if _, err := os.Stat(p.Token); !os.IsNotExist(err) {
		t.Fatal("stale token file was not removed")
	}
}

func TestZombieIsNotAlive(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc")
	}
	proc, err := os.StartProcess("/bin/true", []string{"true"}, &os.ProcAttr{})
	if err != nil {
		t.Skip("cannot start /bin/true:", err)
	}
	defer proc.Wait()
	// Not yet waited for: once it exits it stays a zombie until proc.Wait.
	deadline := time.Now().Add(5 * time.Second)
	for processAlive(proc.Pid) {
		if time.Now().After(deadline) {
			t.Fatal("exited, unreaped child still reported as alive")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
