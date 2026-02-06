package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

/*
-------------------------------------------------------------
Global flags
-------------------------------------------------------------
*/
var (
	// Основные флаги
	flagDbg = flag.Bool("debug", false, "extra diagnostic output")

	// Флаги управления кэшем
	flagCacheDir = flag.String("cache-dir", "",
		"cache directory (default: .mitre-cache or MITRE_CACHE_DIR env)")
	flagNoCache = flag.Bool("no-cache", false,
		"disable caching")
	flagForceRefresh = flag.Bool("force-refresh", false,
		"force download fresh bundle ignoring cache")

	// Флаги запросов
	flagMitigation = flag.String("mitigation", "",
		"Mitigation external ID (e.g. M1037).")
	flagMitigationName = flag.String("mitigation-name", "",
		"Full mitigation name (case‑insensitive).")

	// Флаги вывода
	flagJSON = flag.Bool("json", false, "Emit JSON array.")
	flagCSV  = flag.Bool("csv", false, "Emit CSV.")
	flagNGQL = flag.Bool("ngql", false, "Emit Nebula Graph INSERT statements.")
	flagHelp = flag.Bool("h", false, "Show help.")
)

/*
-------------------------------------------------------------
Minimal STIX structures we need
-------------------------------------------------------------
*/
type Bundle struct {
	Type        string            `json:"type"`
	SpecVersion string            `json:"spec_version"`
	Objects     []json.RawMessage `json:"objects"`
}

// envelope – only type and id are required for the first pass
type baseObject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Technique / sub‑technique
type attackPattern struct {
	Type         string              `json:"type"`
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	ExternalRefs []externalReference `json:"external_references,omitempty"`
}

// Mitigation
type courseOfAction struct {
	Type         string              `json:"type"`
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	ExternalRefs []externalReference `json:"external_references,omitempty"`
}

// Relationship – we only care about relationship_type == "mitigates"
type relationship struct {
	Type             string `json:"type"`
	ID               string `json:"id"`
	RelationshipType string `json:"relationship_type"`
	SourceRef        string `json:"source_ref"` // mitigation
	TargetRef        string `json:"target_ref"` // technique
}

// External reference (the place where ATT&CK stores the human‑readable ID)
type externalReference struct {
	SourceName string `json:"source_name"` // "mitre-attack"
	ExternalID string `json:"external_id"` // "T1059.001" or "M1037"
	URL        string `json:"url,omitempty"`
}

/*
-------------------------------------------------------------
Helper – pull the ATT&CK external ID from a slice of refs
-------------------------------------------------------------
*/
func externalID(refs []externalReference) (string, bool) {
	for _, r := range refs {
		if strings.EqualFold(r.SourceName, "mitre-attack") && r.ExternalID != "" {
			return r.ExternalID, true
		}
	}
	return "", false
}

/*
-------------------------------------------------------------
Константы и функции для работы с кэшем
-------------------------------------------------------------
*/
const (
	bundleURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

// getCacheDir определяет директорию для кэша с приоритетом:
// 1. Флаг --cache-dir
// 2. Переменная окружения MITRE_CACHE_DIR
// 3. /tmp/.mitre-cache в контейнерах
// 4. .mitre-cache для локальной разработки
// 5. /dev/null если --no-cache
func getCacheDir() string {
	// 1. Проверяем флаг --no-cache
	if *flagNoCache {
		return "/dev/null"
	}

	// 2. Проверяем флаг --cache-dir
	if *flagCacheDir != "" {
		return *flagCacheDir
	}

	// 3. Проверяем переменную окружения (только абсолютный путь — защита от path traversal)
	if dir := os.Getenv("MITRE_CACHE_DIR"); dir != "" {
		cleaned := filepath.Clean(dir)
		if !filepath.IsAbs(cleaned) {
			fmt.Fprintf(os.Stderr, "WARNING: MITRE_CACHE_DIR must be absolute path, ignoring: %s\n", dir)
		} else {
			return cleaned
		}
	}

	// 4. Проверяем, находимся ли мы в контейнере
	if isRunningInContainer() {
		return "/tmp/.mitre-cache"
	}

	// 5. Fallback для локальной разработки
	return ".mitre-cache"
}

// isRunningInContainer проверяет, запущено ли приложение в контейнере
func isRunningInContainer() bool {
	// Проверяем различные признаки контейнера
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return true
	}

	// Проверяем cgroups (Linux)
	if _, err := os.Stat("/proc/self/cgroup"); err == nil {
		if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
			content := string(data)
			if strings.Contains(content, "docker") ||
				strings.Contains(content, "kubepods") ||
				strings.Contains(content, "containerd") {
				return true
			}
		}
	}

	return false
}

/*
-------------------------------------------------------------
Загрузка & кэширование ATT&CK bundle
-------------------------------------------------------------
*/
func fetchBundle() ([]byte, error) {
	// Получаем директорию кэша из окружения
	cacheDir := getCacheDir()

	// -----------------------------------------------------------------
	// DEBUG: выводим информацию о директории кэша
	// -----------------------------------------------------------------
	if *flagDbg {
		fmt.Fprintf(os.Stdout, ">>> fetchBundle() - entry point\n")
		fmt.Fprintf(os.Stdout, ">>> cache directory: %s\n", cacheDir)
		if *flagForceRefresh {
			fmt.Fprintln(os.Stdout, ">>> force refresh enabled")
		}
	}

	// -----------------------------------------------------------------
	// 1️⃣ Проверяем и создаем директорию кэша (если нужно)
	// -----------------------------------------------------------------
	// Не создаем директорию если это /dev/null (отключение кэша)
	if cacheDir != "/dev/null" {
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, fmt.Errorf("create cache directory %s: %w", cacheDir, err)
		}
	}

	bundlePath := filepath.Join(cacheDir, "enterprise-attack.json")

	// -----------------------------------------------------------------
	// 2️⃣ Используем кэшированный бандл если он существует
	// -----------------------------------------------------------------
	// Если cacheDir == "/dev/null", пропускаем проверку кэша
	if cacheDir != "/dev/null" && !*flagForceRefresh {
		if cached, err := os.ReadFile(bundlePath); err == nil {
			if *flagDbg {
				fmt.Fprintln(os.Stdout, ">>> cached bundle found – returning cached data")
				fmt.Fprintf(os.Stdout, ">>> cache file: %s (%d bytes)\n",
					bundlePath, len(cached))
			}
			return cached, nil // fast path – return cache
		} else if !os.IsNotExist(err) {
			// Если ошибка не "файл не существует", логируем но продолжаем
			if *flagDbg {
				fmt.Fprintf(os.Stdout, ">>> cache read error (will download): %v\n", err)
			}
		}
	} else if *flagDbg {
		if *flagForceRefresh {
			fmt.Fprintln(os.Stdout, ">>> force refresh - ignoring cache")
		} else {
			fmt.Fprintln(os.Stdout, ">>> cache disabled")
		}
	}

	// -----------------------------------------------------------------
	// 3️⃣ Загружаем бандл из сети
	// -----------------------------------------------------------------
	if *flagDbg {
		fmt.Fprintln(os.Stdout, ">>> downloading ATT&CK bundle")
	}
	data, err := downloadBundle()
	if err != nil {
		return nil, err
	}

	if *flagDbg {
		fmt.Fprintf(os.Stdout, ">>> downloaded bundle (%d bytes)\n", len(data))
	}

	// -----------------------------------------------------------------
	// 4️⃣ Кэшируем скачанный бандл (если кэш не отключен)
	// -----------------------------------------------------------------
	if cacheDir != "/dev/null" {
		if *flagDbg {
			fmt.Fprintf(os.Stdout, ">>> caching to: %s\n", bundlePath)
		}
		// Создаем временный файл для атомарной записи
		tmpPath := bundlePath + ".tmp"
		if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
			if *flagDbg {
				fmt.Fprintf(os.Stdout, ">>> WARNING: failed to write cache: %v\n", err)
			}
			// Если не удалось записать кэш, все равно возвращаем данные
		} else {
			// Атомарно переименовываем временный файл в целевой
			if err := os.Rename(tmpPath, bundlePath); err != nil {
				if *flagDbg {
					fmt.Fprintf(os.Stdout, ">>> WARNING: failed to rename cache file: %v\n", err)
				}
				// Пытаемся удалить временный файл
				os.Remove(tmpPath)
			} else if *flagDbg {
				fmt.Fprintln(os.Stdout, ">>> cache saved successfully")
			}
		}
	}

	return data, nil
}

/* ---------- helper used by fetchBundle ---------- */
func downloadBundle() ([]byte, error) {
	if *flagDbg {
		fmt.Fprintf(os.Stdout, ">>> downloading from: %s\n", bundleURL)
	}

	// Создаем HTTP клиент с таймаутом
	client := &http.Client{
		Timeout: 5 * time.Minute, // Долгая загрузка больших файлов
	}

	resp, err := client.Get(bundleURL)
	if err != nil {
		return nil, fmt.Errorf("download bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle HTTP %d", resp.StatusCode)
	}

	// Читаем с ограничением по размеру (например, 200MB)
	maxSize := 200 * 1024 * 1024 // 200MB
	limitedReader := &io.LimitedReader{R: resp.Body, N: int64(maxSize)}

	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if limitedReader.N <= 0 {
		return nil, fmt.Errorf("bundle too large (max %d MB)", maxSize/1024/1024)
	}

	return data, nil
}

/*
-------------------------------------------------------------
Core extraction logic
-------------------------------------------------------------
*/
type techniqueInfo struct {
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
}

func main() {
	/* ---------------------------------------------------------
	   Парсинг флагов
	   --------------------------------------------------------- */
	flag.Parse()

	// Если запрошен help, показываем его и выходим с кодом 0
	if *flagHelp {
		printUsage()
		os.Exit(0)
	}

	// Если не указаны обязательные флаги, показываем help и выходим с ошибкой
	if *flagMitigation == "" && *flagMitigationName == "" {
		printUsage()
		fmt.Fprintln(os.Stderr, "\nERROR: must specify -mitigation or -mitigation-name")
		os.Exit(1)
	}

	/* ---------------------------------------------------------
	   Load the ATT&CK bundle
	   --------------------------------------------------------- */
	raw, err := fetchBundle()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching ATT&CK bundle: %v\n", err)
		os.Exit(1)
	}
	var bundle Bundle
	if err = json.Unmarshal(raw, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing bundle JSON: %v\n", err)
		os.Exit(1)
	}

	/* ---------------------------------------------------------
	   Build lookup maps (mitigations, techniques, relationships)
	   --------------------------------------------------------- */
	mitMap := make(map[string]courseOfAction) // key = STIX ID
	techMap := make(map[string]attackPattern) // key = STIX ID
	var rels []relationship

	for _, rawObj := range bundle.Objects {
		var bo baseObject
		if err = json.Unmarshal(rawObj, &bo); err != nil {
			continue // ignore malformed entries
		}
		switch bo.Type {
		case "course-of-action":
			var co courseOfAction
			if err = json.Unmarshal(rawObj, &co); err == nil {
				mitMap[co.ID] = co
			}
		case "attack-pattern":
			var ap attackPattern
			if err = json.Unmarshal(rawObj, &ap); err == nil {
				techMap[ap.ID] = ap
			}
		case "relationship":
			var r relationship
			if err = json.Unmarshal(rawObj, &r); err == nil {
				rels = append(rels, r)
			}
		}
	}

	/* ---------------------------------------------------------
	   Find the mitigation requested by the user
	   --------------------------------------------------------- */
	var chosenMitSTIXID string // STIX ID we will match on source_ref
	if *flagMitigation != "" {
		// lookup by external ID (Mxxxx)
		for id, co := range mitMap {
			if ext, ok := externalID(co.ExternalRefs); ok && strings.EqualFold(ext, *flagMitigation) {
				chosenMitSTIXID = id
				break
			}
		}
		if chosenMitSTIXID == "" {
			fmt.Fprintf(os.Stderr, "mitigation %s not found in ATT&CK data\n", *flagMitigation)
			os.Exit(1)
		}
	} else {
		// lookup by name (case‑insensitive)
		target := strings.TrimSpace(*flagMitigationName)
		for id, co := range mitMap {
			if strings.EqualFold(co.Name, target) {
				chosenMitSTIXID = id
				break
			}
		}
		if chosenMitSTIXID == "" {
			fmt.Fprintf(os.Stderr, "mitigation name %q not found (check spelling)\n", target)
			os.Exit(1)
		}
	}

	/* ---------------------------------------------------------
	   Collect all techniques that this mitigation mitigates
	   --------------------------------------------------------- */
	var results []techniqueInfo
	for _, r := range rels {
		if r.RelationshipType != "mitigates" {
			continue
		}
		if r.SourceRef != chosenMitSTIXID {
			continue
		}
		if tp, ok := techMap[r.TargetRef]; ok {
			ext, _ := externalID(tp.ExternalRefs)
			if ext == "" {
				ext = strings.TrimPrefix(tp.ID, "attack-pattern--")
			}
			results = append(results, techniqueInfo{
				ExternalID: ext,
				Name:       tp.Name,
			})
		}
	}
	// deterministic ordering – nice for CSV/JSON diffing
	sort.Slice(results, func(i, j int) bool {
		return results[i].ExternalID < results[j].ExternalID
	})

	/* ---------------------------------------------------------
	   Emit the requested output format
	   --------------------------------------------------------- */
	if *flagNGQL {
		emitNGQL(chosenMitSTIXID, results, mitMap[chosenMitSTIXID])
		return
	}
	if *flagJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}
	if *flagCSV {
		w := csv.NewWriter(os.Stdout)
		_ = w.Write([]string{"Mitigation ID", "Mitigation Name", "Technique ID", "Technique Name"})
		mitExt, _ := externalID(mitMap[chosenMitSTIXID].ExternalRefs)
		for _, t := range results {
			_ = w.Write([]string{mitExt, mitMap[chosenMitSTIXID].Name, t.ExternalID, t.Name})
		}
		w.Flush()
		return
	}
	// default: pretty table
	printTable(chosenMitSTIXID, mitMap[chosenMitSTIXID], results)
}

/*
-------------------------------------------------------------
Функция для вывода справки
-------------------------------------------------------------
*/
func printUsage() {
	fmt.Printf(`Usage: %s -mitigation Mxxxx [options]
Options:
   -mitigation          ATT&CK mitigation external ID (Mxxxx)
   -mitigation-name    Full mitigation name (case‑insensitive)
   
Output formats:
   -json                Output JSON
   -csv                 Output CSV
   -ngql                Output Nebula Graph INSERT statements
   
Cache control:
   --cache-dir DIR      Cache directory (default: MITRE_CACHE_DIR env or .mitre-cache)
   --no-cache           Disable caching
   --force-refresh      Force download fresh bundle ignoring cache
   
Debug:
   -debug               Extra diagnostic output
   -h                   Show this help

Environment variables:
   MITRE_CACHE_DIR      Cache directory (overrides default)

Examples:
   %s -mitigation M1037
   %s -mitigation M1037 -json
   %s -mitigation M1037 --no-cache
   MITRE_CACHE_DIR=/cache %s -mitigation M1037 --force-refresh
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

/*
-------------------------------------------------------------
Pretty‑print table (default output)
-------------------------------------------------------------
*/
func printTable(mitSTIX string, mit courseOfAction, data []techniqueInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	mitExt, _ := externalID(mit.ExternalRefs)
	fmt.Fprintf(w, "MITIGATION\t%s (%s)\n", mit.Name, mitExt)
	fmt.Fprintln(w, "---------------------------------------------------------------")
	fmt.Fprintln(w, "TECHNIQUE ID\tTECHNIQUE NAME")
	for _, t := range data {
		fmt.Fprintf(w, "%s\t%s\n", t.ExternalID, t.Name)
	}
	_ = w.Flush()
}

/*
-------------------------------------------------------------
Nebula Graph nGQL generation
-------------------------------------------------------------
*/
func quoteID(s string) string {
	return "`" + strings.ReplaceAll(s, "`", "``") + "`"
}
func quoteLiteral(s string) string { return strconv.Quote(s) }

func emitNGQL(mitSTIX string, techs []techniqueInfo, mit courseOfAction) {
	var b strings.Builder
	mitExt, _ := externalID(mit.ExternalRefs)

	// mitigation vertex
	fmt.Fprintf(&b, "INSERT VERTEX mitigation(id, name) VALUES %s:(%s, %s);\n",
		quoteID(mitExt), quoteLiteral(mitExt), quoteLiteral(mit.Name))

	// technique vertices
	for _, t := range techs {
		fmt.Fprintf(&b, "INSERT VERTEX technique(id, name) VALUES %s:(%s, %s);\n",
			quoteID(t.ExternalID), quoteLiteral(t.ExternalID), quoteLiteral(t.Name))
	}

	// edges: mitigation -> technique
	for _, t := range techs {
		fmt.Fprintf(&b, "INSERT EDGE mitigates() VALUES %s -> %s;\n",
			quoteID(mitExt), quoteID(t.ExternalID))
	}
	fmt.Print(b.String())
}
