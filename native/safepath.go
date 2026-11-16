package wormhole

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The file name of an incoming transfer is chosen by the remote peer
// (wormhole-william passes offer.File.FileName through unchanged), so it must
// never be used as a path: "..\..\AppData\...\Startup\x.bat" would land
// outside the receive folder.

var reservedWinNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// sanitizeFileName reduces a peer-supplied name to a single path element.
func sanitizeFileName(name string) (string, error) {
	// Treat both separators as separators regardless of OS, then keep the last element.
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.LastIndex(name, ":"); i >= 0 { // drive letter / ADS
		name = name[i+1:]
	}
	name = strings.TrimRight(strings.TrimSpace(name), ". ")
	if name == "" || name == "." || name == ".." {
		return "", errors.New("недопустимое имя файла")
	}
	stem := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if reservedWinNames[strings.TrimSpace(stem)] {
		return "", fmt.Errorf("зарезервированное имя файла: %q", name)
	}
	return name, nil
}

// createOutputFile creates a new file for a peer-named transfer directly inside
// destDir. It never overwrites: an existing name gets a " (N)" suffix.
func createOutputFile(destDir, peerName string) (*os.File, string, error) {
	name, err := sanitizeFileName(peerName)
	if err != nil {
		return nil, "", err
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 0; i < 1000; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		p := filepath.Join(destDir, candidate)
		if filepath.Dir(p) != filepath.Clean(destDir) {
			return nil, "", fmt.Errorf("имя файла выходит за папку назначения: %q", peerName)
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			return f, p, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("не удалось подобрать свободное имя для %q", name)
}
