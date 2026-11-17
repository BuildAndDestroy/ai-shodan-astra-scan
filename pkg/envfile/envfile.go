// Package envfile loads simple KEY=VALUE pairs from a .env file into the
// process environment without overriding variables that are already set.
package envfile

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Load reads path (if it exists) and sets any variables not already present
// in the environment. A missing file is not an error.
func Load(path string) error {
	// #nosec G304 -- path is an operator-supplied CLI flag pointing at a local .env file
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if _, exists := os.LookupEnv(key); !exists && value != "" {
			if err := os.Setenv(key, value); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}
