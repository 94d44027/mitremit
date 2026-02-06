// Интеграционные тесты валидации MITRE_CACHE_DIR (защита от path traversal).
// Проверяют, что принимается только абсолютный путь; относительный игнорируется с предупреждением.
package tests

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	envMITRECacheDir = "MITRE_CACHE_DIR"
	warningPrefix    = "WARNING: MITRE_CACHE_DIR must be absolute path"
	cacheDirLine     = ">>> cache directory:"
)

// getBinary строит бинарник mitremit в временную директорию и возвращает путь к нему.
func getBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "mitremit")
	if goExe := os.Getenv("GOEXE"); goExe != "" {
		bin += goExe
	} else if os.PathListSeparator == ';' {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = repoRoot(t)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("build mitremit: %v", err)
	}
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	// При вызове "go test ./tests/" рабочая директория — корень модуля
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// Если тест запущен из tests/, поднимаемся на уровень выше
	if filepath.Base(wd) == "tests" {
		return filepath.Dir(wd)
	}
	return wd
}

// runMitremit запускает бинарник с заданным env и аргументами, возвращает stdout и stderr.
func runMitremit(t *testing.T, binary string, env map[string]string, args ...string) (stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Dir = repoRoot(t)
	envList := os.Environ()
	for k := range env {
		// Удаляем существующую переменную из окружения
		prefix := k + "="
		filtered := envList[:0]
		for _, e := range envList {
			if !strings.HasPrefix(e, prefix) {
				filtered = append(filtered, e)
			}
		}
		envList = filtered
	}
	for k, v := range env {
		envList = append(envList, k+"="+v)
	}
	cmd.Env = envList
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	_ = cmd.Run() // нас интересует только вывод, не exit code (при отсутствии сети может быть ошибка)
	return outBuf.String(), errBuf.String()
}

func TestMITRECacheDir_AbsolutePathAccepted(t *testing.T) {
	bin := getBinary(t)
	absDir := filepath.Join(t.TempDir(), "mitremit-cache-abs")
	stdout, stderr := runMitremit(t, bin, map[string]string{envMITRECacheDir: absDir},
		"-debug", "-mitigation", "M1037")

	// Должны увидеть использование заданной абсолютной директории (нормализованной)
	expectDir := filepath.Clean(absDir)
	if !strings.Contains(stdout, cacheDirLine) {
		t.Fatalf("expected stdout to contain %q; stdout:\n%s\nstderr:\n%s", cacheDirLine, stdout, stderr)
	}
	if !strings.Contains(stdout, expectDir) {
		t.Errorf("expected stdout to contain cache directory %q; stdout:\n%s", expectDir, stdout)
	}
	if strings.Contains(stderr, warningPrefix) {
		t.Errorf("absolute path must not trigger WARNING; stderr:\n%s", stderr)
	}
}

func TestMITRECacheDir_RelativePathIgnoredWithWarning(t *testing.T) {
	bin := getBinary(t)
	stdout, stderr := runMitremit(t, bin, map[string]string{envMITRECacheDir: "../../tmp/evil"},
		"-debug", "-mitigation", "M1037")

	// Должно быть предупреждение в stderr
	if !strings.Contains(stderr, warningPrefix) {
		t.Errorf("expected stderr to contain %q; stderr:\n%s\nstdout:\n%s", warningPrefix, stderr, stdout)
	}
	// Игнорируемое значение должно быть в сообщении
	if !strings.Contains(stderr, "../../tmp/evil") {
		t.Errorf("expected stderr to show ignored value; stderr:\n%s", stderr)
	}
	// Должна использоваться fallback-директория (не относительный путь атакующего)
	if !strings.Contains(stdout, cacheDirLine) {
		t.Fatalf("expected stdout to contain %q; stdout:\n%s", cacheDirLine, stdout)
	}
	// Fallback: .mitre-cache или /tmp/.mitre-cache в контейнере
	if strings.Contains(stdout, ">>> cache directory: ../../tmp/evil") {
		t.Errorf("relative path must not be used as cache directory; stdout:\n%s", stdout)
	}
}

func TestMITRECacheDir_CleanedAbsolutePath(t *testing.T) {
	bin := getBinary(t)
	// Путь с лишними слэшами и .. внутри — должен быть нормализован
	tmpBase := t.TempDir()
	absWithDots := filepath.Join(tmpBase, "a", "..", "b") // в итоге <tmp>/b
	cleaned := filepath.Clean(absWithDots)
	stdout, _ := runMitremit(t, bin, map[string]string{envMITRECacheDir: absWithDots},
		"-debug", "-mitigation", "M1037")

	if !strings.Contains(stdout, cacheDirLine) {
		t.Fatalf("expected stdout to contain %q; stdout:\n%s", cacheDirLine, stdout)
	}
	if !strings.Contains(stdout, cleaned) {
		t.Errorf("expected cleaned absolute path %q in stdout; got:\n%s", cleaned, stdout)
	}
}
