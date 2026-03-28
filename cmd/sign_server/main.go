// Command sign_server runs a small HTTP server on the host that signs Windows PEs
// with scripts/sign_windows.sh (PKCS#11 / USB token). GoReleaser inside Docker can call
// http://host.docker.internal:<port>/sign so the binary is signed on the host filesystem
// (same volume mount as the container).
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	addr := os.Getenv("SIGN_SERVER_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8765"
	}
	repoRoot := os.Getenv("SIGN_SERVER_REPO_ROOT")
	if repoRoot == "" {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatal(err)
		}
		repoRoot = wd
	}
	var err error
	repoRoot, err = filepath.Abs(repoRoot)
	if err != nil {
		log.Fatal(err)
	}
	token := os.Getenv("SIGN_SERVER_TOKEN")

	mux := http.NewServeMux()
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if got != token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		var body struct {
			Path string `json:"path"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		abs, err := safeArtifactPath(repoRoot, body.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		script := filepath.Join(repoRoot, "scripts", "sign_windows.sh")
		cmd := exec.Command("bash", script, abs)
		cmd.Dir = repoRoot
		cmd.Env = signEnv(os.Environ())
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("sign failed: %v", err)
			http.Error(w, "sign failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("sign_server listening on http://%s (repo %s)", addr, repoRoot)
	if err := http.ListenAndServe(addr, mux); err != nil {
		if strings.Contains(err.Error(), "address already in use") {
			log.Fatalf("%v: another sign_server may still be running; try `make sign-server-stop` or set SIGN_SERVER_ADDR to a free port", err)
		}
		log.Fatal(err)
	}
}

func signEnv(environ []string) []string {
	out := make([]string, 0, len(environ)+2)
	for _, e := range environ {
		if strings.HasPrefix(e, "SIGN_HTTP_URL=") {
			continue
		}
		if strings.HasPrefix(e, "SKIP_CODE_SIGN=") {
			continue
		}
		out = append(out, e)
	}
	out = append(out, "SKIP_CODE_SIGN=0", "SIGN_HTTP_URL=")
	return out
}

func safeArtifactPath(repoRoot, rel string) (string, error) {
	rel = filepath.Clean(filepath.FromSlash(rel))
	if rel == "." || strings.HasPrefix(rel, "..") {
		return "", errors.New("invalid path")
	}
	distPrefix := "dist" + string(os.PathSeparator)
	if !strings.HasPrefix(rel, distPrefix) {
		return "", errors.New("path must be under dist/")
	}
	if filepath.Ext(rel) != ".exe" {
		return "", errors.New("path must end with .exe")
	}
	rootClean := filepath.Clean(repoRoot)
	abs := filepath.Join(rootClean, rel)
	absClean := filepath.Clean(abs)
	relTo, err := filepath.Rel(rootClean, absClean)
	if err != nil || strings.HasPrefix(relTo, "..") {
		return "", errors.New("path escapes repo root")
	}
	st, err := os.Stat(absClean)
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}
	if st.IsDir() {
		return "", errors.New("not a file")
	}
	return absClean, nil
}
