package main

import (
	"os"
	"path/filepath"
	"strings"
)

// The wormhole: protocol handler is reachable from any web page, so URI
// payloads are untrusted input (serg/tasks#3045).

// receiveFolders are the only folders wormhole:openfolder may open.
func receiveFolders() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return []string{desktopDir()}
	}
	return []string{desktopDir(), filepath.Join(home, "Desktop"), filepath.Join(home, "Downloads")}
}

// isAllowedOpenFolder reports whether p is one of the allowed folders and is an
// existing directory (explorer given a file path opens/runs that file).
func isAllowedOpenFolder(p string, allowed []string) bool {
	clean := filepath.Clean(p)
	fi, err := os.Stat(clean)
	if err != nil || !fi.IsDir() {
		return false
	}
	for _, a := range allowed {
		if strings.EqualFold(clean, filepath.Clean(a)) {
			return true
		}
	}
	return false
}

// matchPending returns the relay entry for codeID if the relay queued exactly
// this code for this device.
func matchPending(pending []pendingCode, code, codeID string) (pendingCode, bool) {
	for _, pc := range pending {
		if pc.ID == codeID && pc.Code == code && codeID != "" {
			return pc, true
		}
	}
	return pendingCode{}, false
}
