package main

import (
	"os"
	"path/filepath"
	"testing"
)

// wormhole:openfolder:<path> comes from any web page; only the known receive
// folders may be opened, never a file (explorer would run it).
func TestOpenFolderAllowed(t *testing.T) {
	root := t.TempDir()
	desk := filepath.Join(root, "Desktop")
	os.Mkdir(desk, 0o755)
	exe := filepath.Join(desk, "payload.bat")
	os.WriteFile(exe, []byte("x"), 0o644)
	allowed := []string{desk, filepath.Join(root, "Downloads")}

	if !isAllowedOpenFolder(desk, allowed) {
		t.Error("receive folder rejected")
	}
	if !isAllowedOpenFolder(desk+`\`, allowed) {
		t.Error("receive folder with trailing slash rejected")
	}
	for _, p := range []string{exe, root, `C:\Windows\System32\calc.exe`, `\attacker\share\x.exe`, filepath.Join(root, "Downloads")} {
		if isAllowedOpenFolder(p, allowed) {
			t.Errorf("%q allowed", p)
		}
	}
}

// wormhole:receive:<code>:<id>:<name> must only start a download for a code the
// relay actually queued for this device.
func TestMatchPending(t *testing.T) {
	pending := []pendingCode{{ID: "a1", Code: "7-crossover-clockwork", Filename: "photo.jpg"}}
	if pc, ok := matchPending(pending, "7-crossover-clockwork", "a1"); !ok || pc.Filename != "photo.jpg" {
		t.Errorf("queued code rejected: %+v %v", pc, ok)
	}
	if _, ok := matchPending(pending, "9-attacker-code", "a1"); ok {
		t.Error("foreign code accepted for a known id")
	}
	if _, ok := matchPending(pending, "7-crossover-clockwork", "zz"); ok {
		t.Error("unknown id accepted")
	}
	if _, ok := matchPending(nil, "7-crossover-clockwork", "a1"); ok {
		t.Error("accepted with no pending codes")
	}
}
