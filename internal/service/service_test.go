package service

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestStateAndTokenFiles(t *testing.T) {
	p := NewPaths(filepath.Join(t.TempDir(), "state"))
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	// Windows has no Unix permission bits (os reports 0777/0666).
	if info, _ := os.Stat(p.Dir); runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", info.Mode().Perm())
	}
	if st, err := p.ReadState(); st != nil || err != nil {
		t.Fatalf("empty dir: %v %v", st, err)
	}
	want := State{PID: os.Getpid(), URL: "http://127.0.0.1:7708/", Config: "/etc/tp.yaml", TokenFile: p.Token, Started: time.Now().Round(time.Second)}
	if err := p.WriteState(want); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Token, []byte("tok-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(p.State); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode %v", info.Mode().Perm())
	}
	st, err := p.Running()
	if err != nil || st == nil || st.PID != want.PID || !st.Started.Equal(want.Started) {
		t.Fatalf("Running = %+v, %v", st, err)
	}
	// Cleanup by another pid must not remove a live instance's state.
	p.Cleanup(os.Getpid() + 1)
	if _, err := os.Stat(p.State); err != nil {
		t.Fatal("cleanup by a different pid removed a live instance's state")
	}
	p.Cleanup(os.Getpid())
	if _, err := os.Stat(p.State); !os.IsNotExist(err) {
		t.Fatal("state not removed")
	}
	if _, err := os.Stat(p.Token); err != nil {
		t.Fatal("the persisted token file must survive cleanup")
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
	os.WriteFile(p.Token, []byte("persisted-token-value\n"), 0o600)
	if st, err := p.Running(); st != nil || err != nil {
		t.Fatalf("Running = %+v, %v; want nil for a dead pid", st, err)
	}
	if _, err := os.Stat(p.State); !os.IsNotExist(err) {
		t.Fatal("stale state file was not removed")
	}
	if _, err := os.Stat(p.Token); err != nil {
		t.Fatal("the persisted token file must survive stale-state cleanup")
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
