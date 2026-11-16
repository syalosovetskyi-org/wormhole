package wormhole

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A peer controls msg.Name. Whatever it sends, the file must land directly in
// destDir (serg/tasks#3045: path traversal into Startup).
func TestCreateOutputFileStaysInDestDir(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "Desktop")
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	names := []string{
		`..\..\evil.bat`,
		`../../evil.bat`,
		`..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.bat`,
		`C:\Windows\Temp\abs.bat`,
		`sub/dir/nested.txt`,
	}
	for _, name := range names {
		f, p, err := createOutputFile(dest, name)
		if err != nil {
			t.Fatalf("%q: unexpected error %v", name, err)
		}
		f.Close()
		if filepath.Dir(p) != dest {
			t.Errorf("%q escaped destDir: %s", name, p)
		}
	}
	// Nothing may have been written outside destDir.
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 {
		t.Errorf("files written outside destDir: %v", entries)
	}
}

func TestCreateOutputFileRejectsBadNames(t *testing.T) {
	dest := t.TempDir()
	for _, name := range []string{"", ".", "..", `..\`, "../", "CON", "nul.txt", "COM1", "lpt9.log"} {
		if f, p, err := createOutputFile(dest, name); err == nil {
			f.Close()
			t.Errorf("%q accepted as %s", name, p)
		}
	}
}

func TestCreateOutputFileDoesNotOverwrite(t *testing.T) {
	dest := t.TempDir()
	existing := filepath.Join(dest, "report.pdf")
	if err := os.WriteFile(existing, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, p, err := createOutputFile(dest, "report.pdf")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if p == existing {
		t.Fatalf("existing file reused: %s", p)
	}
	if !strings.HasPrefix(filepath.Base(p), "report (") {
		t.Errorf("unexpected new name %s", p)
	}
	b, _ := os.ReadFile(existing)
	if string(b) != "keep me" {
		t.Errorf("existing file truncated: %q", b)
	}
}
