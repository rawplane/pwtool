package pipeline

import (
	"os"
	"path/filepath"
)

// joinPath joins parts onto the base output directory using filepath.Join.
func joinPath(base string, parts ...string) string {
	all := append([]string{base}, parts...)
	return filepath.Join(all...)
}

// CountLines returns the number of non-empty lines in a file at path. Returns
// 0 if the file does not exist or is empty. Mirrors the bash count_lines().
func CountLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	if len(data) == 0 {
		return 0
	}
	n := 0
	for _, b := range data {
		if b == '\n' {
			n++
		}
	}
	// Count a final line without trailing newline.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// FileExists reports whether a regular file (or dir) exists at path.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsNonEmpty reports whether a file exists and has at least one byte.
func IsNonEmpty(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Size() > 0
}
