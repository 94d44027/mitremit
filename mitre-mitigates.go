// mitre-mitigates-enhanced.go
//
// Enhanced tool that, given a MITRE ATT&CK mitigation (by external ID or by name),
// lists every technique / sub-technique it mitigates, connects to Nebula Graph,
// checks for missing techniques, and generates nGQL scripts to insert them.
//
// It automatically downloads the latest ATT&CK enterprise STIX bundle
// and caches the bundle locally.
//
// Build & run:
//
//   go mod init mitremit
//   go get github.com/vesoft-inc/nebula-go/v3
//   go build -o mitremit mitre-mitigates-enhanced.go
//   export NEBULA_HOST="192.168.1.100"
//   export NEBULA_PORT="9669"
//   export NEBULA_USER="root"
//   export NEBULA_PASS="mypassword"
//   export NEBULA_SPACE="ESP01"
//   ./mitremit -mitigation M1037
//
// Author: Enhanced version based on ChatGPT original (2024-06) – MIT licence.
// --------------------------------------------------------------

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

	nebula "github.com/vesoft-inc/nebula-go/v3"
)

/*
-------------------------------------------------------------
Global flag(s)
-------------------------------------------------------------
*/
var (
	// `-debug` can be placed anywhere on the command line.
	// It defaults to false and is parsed in `main` before any work.
	flagDbg = flag.Bool("debug", false, "extra diagnostic output")
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

// Technique / sub-technique
type attackPattern struct {
	Type         string              `json:"type"`
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	ExternalRefs []externalReference `json:"external_references,omitempty"`
	KillChain    []killChainPhase    `json:"kill_chain_phases,omitempty"`
}

// Kill chain phase (contains tactic info)
type killChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"` // e.g., "execution", "persistence"
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

// External reference (the place where ATT&CK stores the human-readable ID)
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
Download & cache the ATT&CK bundle
-------------------------------------------------------------
*/
const (
	bundleURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
	cacheDir  = ".mitre-cache"
)

func fetchBundle() ([]byte, error) {
	// -----------------------------------------------------------------
	// DEBUG: tell us we entered the function
	// -----------------------------------------------------------------
	if *flagDbg {
		fmt.Fprintln(os.Stdout, ">>> fetchBundle() – entry point")
	}

	// -----------------------------------------------------------------
	// 1️⃣ Ensure a writable cache directory exists
	// -----------------------------------------------------------------
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, err
	}

	bundlePath := filepath.Join(cacheDir, "enterprise-attack.json")

	// -----------------------------------------------------------------
	// 2️⃣ Use cached bundle if it exists
	// -----------------------------------------------------------------
	if cached, err := os.ReadFile(bundlePath); err == nil {
		if *flagDbg {
			fmt.Fprintln(os.Stdout, ">>> cached bundle found – returning cached data")
		}
		return cached, nil // fast path – return cache
	}

	// -----------------------------------------------------------------
	// 3️⃣ Download bundle
	// -----------------------------------------------------------------
	if *flagDbg {
		fmt.Fprintln(os.Stdout, ">>> downloading ATT&CK bundle")
	}

	data, err := downloadBundle()
	if err != nil {
		return nil, err
	}

	if *flagDbg {
		fmt.Fprintf(os.Stdout, ">>> downloaded bundle (%d bytes) – caching\n", len(data))
	}

	_ = os.WriteFile(bundlePath, data, 0o644)
	return data, nil
}

/* ---------- helper used by fetchBundle ---------- */
func downloadBundle() ([]byte, error) {
	resp, err := http.Get(bundleURL)
	if err != nil {
		return nil, fmt.Errorf("download bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

/*
-------------------------------------------------------------
Core extraction logic
-------------------------------------------------------------
*/

type techniqueInfo struct {
	ExternalID string   `json:"external_id"`
	Name       string   `json:"name"`
	Tactics    []string `json:"tactics,omitempty"` // Tactic phase names
}

/*
-------------------------------------------------------------
Nebula Graph connection management
-------------------------------------------------------------
*/

type nebulaConfig struct {
	Host  string
	Port  int
	User  string
	Pass  string
	Space string
}

func getNebulaConfig() nebulaConfig {
	cfg := nebulaConfig{
		Host:  getEnv("NEBULA_HOST", "127.0.0.1"),
		Port:  getEnvInt("NEBULA_PORT", 9669),
		User:  getEnv("NEBULA_USER", "root"),
		Pass:  getEnv("NEBULA_PASS", "nebula"),
		Space: getEnv("NEBULA_SPACE", "ESP01"),
	}
	return cfg
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func connectNebula(cfg nebulaConfig) (*nebula.Session, func(), error) {
	hostAddress := nebula.HostAddress{Host: cfg.Host, Port: cfg.Port}
	poolConfig := nebula.GetDefaultConf()

	pool, err := nebula.NewConnectionPool([]nebula.HostAddress{hostAddress}, poolConfig, nebula.DefaultLogger{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	session, err := pool.GetSession(cfg.User, cfg.Pass)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Switch to space
	useSpaceQuery := fmt.Sprintf("USE %s;", cfg.Space)
	if _, err := session.Execute(useSpaceQuery); err != nil {
		session.Release()
		pool.Close()
		return nil, nil, fmt.Errorf("failed to USE space %s: %w", cfg.Space, err)
	}

	cleanup := func() {
		session.Release()
		pool.Close()
	}

	return session, cleanup, nil
}

/*
-------------------------------------------------------------
Database query functions
-------------------------------------------------------------
*/

func checkMitigationExists(session *nebula.Session, mitigationID string) (bool, error) {
	query := fmt.Sprintf(`MATCH (m:tMitreMitigation) WHERE id(m) == "%s" RETURN id(m) AS mitigation;`, mitigationID)

	if *flagDbg {
		fmt.Fprintf(os.Stderr, ">>> Query: %s\n", query)
	}

	result, err := session.Execute(query)
	if err != nil {
		return false, fmt.Errorf("query failed: %w", err)
	}

	return result.GetRowSize() > 0, nil
}

func findMissingTechniques(session *nebula.Session, techniqueIDs []string) ([]string, error) {
	if len(techniqueIDs) == 0 {
		return nil, nil
	}

	// Build IN clause
	quotedIDs := make([]string, len(techniqueIDs))
	for i, id := range techniqueIDs {
		quotedIDs[i] = fmt.Sprintf(`"%s"`, id)
	}
	inClause := strings.Join(quotedIDs, ", ")

	query := fmt.Sprintf(`MATCH (t:tMitreTechnique) WHERE id(t) IN [%s] RETURN collect(id(t)) AS techniques;`, inClause)

	if *flagDbg {
		fmt.Fprintf(os.Stderr, ">>> Query: %s\n", query)
	}

	result, err := session.Execute(query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}

	var foundTechniques []string
	if result.GetRowSize() > 0 {
		// Get first row
		record, err := result.GetRowValuesByIndex(0)
		if err != nil {
			return nil, fmt.Errorf("failed to get row: %w", err)
		}

		// Get first column value (index 0)
		val, err := record.GetValueByIndex(0)
		if err != nil {
			return nil, fmt.Errorf("failed to get value: %w", err)
		}

		// Check if it's a list
		if val.IsList() {
			list, err := val.AsList()
			if err != nil {
				return nil, fmt.Errorf("failed to convert to list: %w", err)
			}

			// Extract string values from list
			for _, item := range list {
				if item.IsString() {
					str, err := item.AsString()
					if err == nil {
						foundTechniques = append(foundTechniques, str)
					}
				}
			}
		}
	}

	// Find missing
	foundMap := make(map[string]bool)
	for _, id := range foundTechniques {
		foundMap[id] = true
	}

	var missing []string
	for _, id := range techniqueIDs {
		if !foundMap[id] {
			missing = append(missing, id)
		}
	}

	return missing, nil
}

/*
-------------------------------------------------------------
nGQL generation functions
-------------------------------------------------------------
*/

// quoteID wraps an ID in double quotes for nGQL
func quoteID(s string) string {
	// Escape any double quotes in the string by doubling them
	escaped := strings.ReplaceAll(s, `"`, `""`)
	return `"` + escaped + `"`
}

func quoteLiteral(s string) string {
	return strconv.Quote(s)
}

// Helper to determine if technique is a subtechnique
func isSubtechnique(techID string) bool {
	return strings.Contains(techID, ".")
}

// Helper to extract parent technique ID from subtechnique
func getParentTechniqueID(techID string) string {
	if idx := strings.Index(techID, "."); idx > 0 {
		return techID[:idx]
	}
	return techID
}

// Map tactic phase name to tactic ID (based on MITRE ATT&CK Enterprise matrix)
var tacticPhaseToID = map[string]string{
	"reconnaissance":       "TA0043",
	"resource-development": "TA0042",
	"initial-access":       "TA0001",
	"execution":            "TA0002",
	"persistence":          "TA0003",
	"privilege-escalation": "TA0004",
	"defense-evasion":      "TA0005",
	"credential-access":    "TA0006",
	"discovery":            "TA0007",
	"lateral-movement":     "TA0008",
	"collection":           "TA0009",
	"command-and-control":  "TA0011",
	"exfiltration":         "TA0010",
	"impact":               "TA0040",
}

func generateNGQL(mitigationID, mitigationName string, techniques []techniqueInfo, missingTechniques []string) string {
	var b strings.Builder

	b.WriteString("-- ============================================================\n")
	b.WriteString(fmt.Sprintf("-- nGQL script for mitigation %s (%s)\n", mitigationID, mitigationName))
	b.WriteString("-- ============================================================\n\n")

	// Create map of missing techniques for quick lookup
	missingMap := make(map[string]bool)
	for _, id := range missingTechniques {
		missingMap[id] = true
	}

	if len(missingTechniques) > 0 {
		b.WriteString("-- ============================================================\n")
		b.WriteString("-- STEP 1: Insert missing techniques\n")
		b.WriteString("-- ============================================================\n\n")

		for _, t := range techniques {
			if !missingMap[t.ExternalID] {
				continue
			}

			b.WriteString(fmt.Sprintf("INSERT VERTEX IF NOT EXISTS tMitreTechnique(Technique_ID, Technique_Name, Mitre_Attack_Version, rcelpe, priority, execution_min, execution_max) VALUES %s:(%s, %s, \"18.0\", false, 4, 0.1667, 120);\n",
				quoteID(t.ExternalID),
				quoteLiteral(t.ExternalID),
				quoteLiteral(t.Name)))
		}

		b.WriteString("\n-- ============================================================\n")
		b.WriteString("-- STEP 2: Insert has_subtechnique edges (parent to subtechnique)\n")
		b.WriteString("-- ============================================================\n\n")

		for _, t := range techniques {
			if !missingMap[t.ExternalID] {
				continue
			}

			if isSubtechnique(t.ExternalID) {
				parentID := getParentTechniqueID(t.ExternalID)
				b.WriteString(fmt.Sprintf("INSERT EDGE IF NOT EXISTS has_subtechnique VALUES %s->%s@0:();\n",
					quoteID(parentID),
					quoteID(t.ExternalID)))
			}
		}

		b.WriteString("\n-- ============================================================\n")
		b.WriteString("-- STEP 3: Insert part_of edges (technique/subtechnique to tactic)\n")
		b.WriteString("-- ============================================================\n\n")

		for _, t := range techniques {
			if !missingMap[t.ExternalID] {
				continue
			}

			for _, tacticPhase := range t.Tactics {
				if tacticID, ok := tacticPhaseToID[tacticPhase]; ok {
					b.WriteString(fmt.Sprintf("INSERT EDGE IF NOT EXISTS part_of VALUES %s->%s@0:();\n",
						quoteID(t.ExternalID),
						quoteID(tacticID)))
				}
			}
		}

		b.WriteString("\n")
	}

	b.WriteString("-- ============================================================\n")
	b.WriteString("-- STEP 4: Insert mitigates edges (mitigation to techniques)\n")
	b.WriteString("-- ============================================================\n\n")

	for _, t := range techniques {
		b.WriteString(fmt.Sprintf("INSERT EDGE IF NOT EXISTS mitigates VALUES %s->%s@0:(NULL, \"Enterprise\");\n",
			quoteID(mitigationID),
			quoteID(t.ExternalID)))
	}

	b.WriteString("\n-- ============================================================\n")
	b.WriteString("-- STEP 5: Verification query\n")
	b.WriteString("-- ============================================================\n\n")

	b.WriteString(fmt.Sprintf("-- Run this to verify the mitigation has correct edge count:\n"))
	b.WriteString(fmt.Sprintf("-- MATCH (m:tMitreMitigation)-[e:mitigates]->(t) WHERE id(m) == \"%s\" RETURN COUNT(e);\n", mitigationID))
	b.WriteString(fmt.Sprintf("-- Expected count: %d\n\n", len(techniques)))

	return b.String()
}

/*
-------------------------------------------------------------
Execute nGQL statements against database
-------------------------------------------------------------
*/
func executeNGQL(session *nebula.Session, mitigationID, mitigationName string, techniques []techniqueInfo, missingTechniques []string) error {
	// Create map of missing techniques for quick lookup
	missingMap := make(map[string]bool)
	for _, id := range missingTechniques {
		missingMap[id] = true
	}

	// Count statements
	var techInserts, subtechEdges, tacticEdges, mitigatesEdges int
	for _, t := range techniques {
		if missingMap[t.ExternalID] {
			techInserts++
			if isSubtechnique(t.ExternalID) {
				subtechEdges++
			}
			for _, tacticPhase := range t.Tactics {
				if _, ok := tacticPhaseToID[tacticPhase]; ok {
					tacticEdges++
				}
			}
		}
	}
	mitigatesEdges = len(techniques)

	// Display planned nGQL statements
	script := generateNGQL(mitigationID, mitigationName, techniques, missingTechniques)
	fmt.Fprintf(os.Stderr, "%s", script)

	// Display summary
	fmt.Fprintf(os.Stderr, "=============================================================\n")
	fmt.Fprintf(os.Stderr, "EXECUTION SUMMARY for %s (%s)\n", mitigationName, mitigationID)
	fmt.Fprintf(os.Stderr, "=============================================================\n")
	fmt.Fprintf(os.Stderr, "Missing techniques to insert:        %d\n", techInserts)
	fmt.Fprintf(os.Stderr, "has_subtechnique edges to create:    %d\n", subtechEdges)
	fmt.Fprintf(os.Stderr, "part_of edges to create:             %d\n", tacticEdges)
	fmt.Fprintf(os.Stderr, "mitigates edges to create:           %d\n", mitigatesEdges)
	fmt.Fprintf(os.Stderr, "=============================================================\n\n")

	// Ask for confirmation
	fmt.Fprintf(os.Stderr, "Proceed with execution? (yes/no): ")
	var response string
	fmt.Scanln(&response)
	response = strings.ToLower(strings.TrimSpace(response))

	if response != "yes" && response != "y" {
		fmt.Fprintf(os.Stderr, "Execution cancelled by user.\n")
		return nil
	}

	fmt.Fprintf(os.Stderr, "\nExecuting statements...\n")

	// STEP 1: Insert missing techniques
	if techInserts > 0 {
		fmt.Fprintf(os.Stderr, "\nSTEP 1: Inserting %d missing techniques...\n", techInserts)
		for _, t := range techniques {
			if !missingMap[t.ExternalID] {
				continue
			}

			stmt := fmt.Sprintf("INSERT VERTEX IF NOT EXISTS tMitreTechnique(Technique_ID, Technique_Name, Mitre_Attack_Version, rcelpe, priority, execution_min, execution_max) VALUES %s:(%s, %s, \"18.0\", false, 4, 0.1667, 120);",
				quoteID(t.ExternalID),
				quoteLiteral(t.ExternalID),
				quoteLiteral(t.Name))

			if *flagDbg {
				fmt.Fprintf(os.Stderr, ">>> Executing: %s\n", stmt)
			}

			if _, err := session.Execute(stmt); err != nil {
				return fmt.Errorf("failed to insert technique %s: %w", t.ExternalID, err)
			}
		}
		fmt.Fprintf(os.Stderr, "✓ Inserted %d techniques\n", techInserts)
	}

	// STEP 2: Insert has_subtechnique edges
	if subtechEdges > 0 {
		fmt.Fprintf(os.Stderr, "\nSTEP 2: Creating %d has_subtechnique edges...\n", subtechEdges)
		for _, t := range techniques {
			if !missingMap[t.ExternalID] {
				continue
			}

			if isSubtechnique(t.ExternalID) {
				parentID := getParentTechniqueID(t.ExternalID)
				stmt := fmt.Sprintf("INSERT EDGE IF NOT EXISTS has_subtechnique VALUES %s->%s@0:();",
					quoteID(parentID),
					quoteID(t.ExternalID))

				if *flagDbg {
					fmt.Fprintf(os.Stderr, ">>> Executing: %s\n", stmt)
				}

				if _, err := session.Execute(stmt); err != nil {
					return fmt.Errorf("failed to insert has_subtechnique edge %s->%s: %w", parentID, t.ExternalID, err)
				}
			}
		}
		fmt.Fprintf(os.Stderr, "✓ Created %d has_subtechnique edges\n", subtechEdges)
	}

	// STEP 3: Insert part_of edges
	if tacticEdges > 0 {
		fmt.Fprintf(os.Stderr, "\nSTEP 3: Creating %d part_of edges...\n", tacticEdges)
		for _, t := range techniques {
			if !missingMap[t.ExternalID] {
				continue
			}

			for _, tacticPhase := range t.Tactics {
				if tacticID, ok := tacticPhaseToID[tacticPhase]; ok {
					stmt := fmt.Sprintf("INSERT EDGE IF NOT EXISTS part_of VALUES %s->%s@0:();",
						quoteID(t.ExternalID),
						quoteID(tacticID))

					if *flagDbg {
						fmt.Fprintf(os.Stderr, ">>> Executing: %s\n", stmt)
					}

					if _, err := session.Execute(stmt); err != nil {
						return fmt.Errorf("failed to insert part_of edge %s->%s: %w", t.ExternalID, tacticID, err)
					}
				}
			}
		}
		fmt.Fprintf(os.Stderr, "✓ Created %d part_of edges\n", tacticEdges)
	}

	// STEP 4: Insert mitigates edges
	fmt.Fprintf(os.Stderr, "\nSTEP 4: Creating %d mitigates edges...\n", mitigatesEdges)
	for _, t := range techniques {
		stmt := fmt.Sprintf("INSERT EDGE IF NOT EXISTS mitigates VALUES %s->%s@0:(NULL, \"Enterprise\");",
			quoteID(mitigationID),
			quoteID(t.ExternalID))

		if *flagDbg {
			fmt.Fprintf(os.Stderr, ">>> Executing: %s\n", stmt)
		}

		if _, err := session.Execute(stmt); err != nil {
			return fmt.Errorf("failed to insert mitigates edge %s->%s: %w", mitigationID, t.ExternalID, err)
		}
	}
	fmt.Fprintf(os.Stderr, "✓ Created %d mitigates edges\n", mitigatesEdges)

	// STEP 5: Verification
	fmt.Fprintf(os.Stderr, "\nSTEP 5: Verification...\n")
	verifyQuery := fmt.Sprintf(`MATCH (m:tMitreMitigation)-[e:mitigates]->(t) WHERE id(m) == "%s" RETURN COUNT(e);`, mitigationID)

	if *flagDbg {
		fmt.Fprintf(os.Stderr, ">>> Executing: %s\n", verifyQuery)
	}

	result, err := session.Execute(verifyQuery)
	if err != nil {
		return fmt.Errorf("verification query failed: %w", err)
	}

	var actualCount int64
	if result.GetRowSize() > 0 {
		record, err := result.GetRowValuesByIndex(0)
		if err != nil {
			return fmt.Errorf("failed to get verification result: %w", err)
		}

		val, err := record.GetValueByIndex(0)
		if err != nil {
			return fmt.Errorf("failed to get count value: %w", err)
		}

		if val.IsInt() {
			actualCount, _ = val.AsInt()
		}
	}

	fmt.Fprintf(os.Stderr, "\n=============================================================\n")
	fmt.Fprintf(os.Stderr, "VERIFICATION RESULTS\n")
	fmt.Fprintf(os.Stderr, "=============================================================\n")
	fmt.Fprintf(os.Stderr, "Expected mitigates edges: %d\n", len(techniques))
	fmt.Fprintf(os.Stderr, "Actual mitigates edges:   %d\n", actualCount)

	if int(actualCount) == len(techniques) {
		fmt.Fprintf(os.Stderr, "Status:                   ✓ SUCCESS\n")
	} else {
		fmt.Fprintf(os.Stderr, "Status:                   ✗ MISMATCH\n")
	}
	fmt.Fprintf(os.Stderr, "=============================================================\n")

	return nil
}

/*
-------------------------------------------------------------
Main function
-------------------------------------------------------------
*/

func main() {
	/* ---------------------------------------------------------
	   Define command-line flags
	   --------------------------------------------------------- */
	mitID := flag.String("mitigation", "", "Mitigation external ID (e.g. M1037).")
	mitName := flag.String("mitigation-name", "", "Full mitigation name (case-insensitive).")
	flagJSON := flag.Bool("json", false, "Emit JSON array.")
	flagCSV := flag.Bool("csv", false, "Emit CSV.")
	flagNGQL := flag.Bool("ngql", false, "Emit Nebula Graph INSERT statements.")
	flagExecute := flag.Bool("execute", false, "Execute INSERT statements against database (interactive).")
	flagNoDB := flag.Bool("no-db", false, "Skip database connection (show techniques only).")
	flagHelp := flag.Bool("h", false, "Show help.")
	// flagDbg is already declared globally

	/* ---------------------------------------------------------
	   IMPORTANT: parse flags *before* any work that uses them
	   --------------------------------------------------------- */
	flag.Parse()

	if *flagHelp || (*mitID == "" && *mitName == "") {
		fmt.Fprintf(os.Stderr,
			`Usage: %s -mitigation Mxxxx [options]

Options:
  -mitigation       ATT&CK mitigation external ID (Mxxxx)
  -mitigation-name  Full mitigation name (case-insensitive)
  -json             Output JSON
  -csv              Output CSV
  -ngql             Output Nebula Graph INSERT statements (with DB check)
  -execute          Execute INSERT statements against database (interactive)
  -no-db            Skip database connection (show techniques only)
  -debug            Extra diagnostic output
  -h                Show this help

Environment Variables (for -ngql and -execute modes):
  NEBULA_HOST       Database hostname/IP (default: 127.0.0.1)
  NEBULA_PORT       Database port (default: 9669)
  NEBULA_USER       Username (default: root)
  NEBULA_PASS       Password (default: nebula)
  NEBULA_SPACE      Space name (default: ESP01)

`, os.Args[0])
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

	if *mitID != "" {
		// lookup by external ID (Mxxxx)
		for id, co := range mitMap {
			if ext, ok := externalID(co.ExternalRefs); ok && strings.EqualFold(ext, *mitID) {
				chosenMitSTIXID = id
				break
			}
		}
		if chosenMitSTIXID == "" {
			fmt.Fprintf(os.Stderr, "mitigation %s not found in ATT&CK data\n", *mitID)
			os.Exit(1)
		}
	} else {
		// lookup by name (case-insensitive)
		target := strings.TrimSpace(*mitName)
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
	seenTechniques := make(map[string]bool) // deduplicate techniques

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

			// Skip if we've already seen this technique
			if seenTechniques[ext] {
				if *flagDbg {
					fmt.Fprintf(os.Stderr, ">>> Skipping duplicate technique: %s\n", ext)
				}
				continue
			}
			seenTechniques[ext] = true

			// Extract tactics from kill chain phases
			var tactics []string
			for _, kc := range tp.KillChain {
				if kc.KillChainName == "mitre-attack" {
					tactics = append(tactics, kc.PhaseName)
				}
			}

			results = append(results, techniqueInfo{
				ExternalID: ext,
				Name:       tp.Name,
				Tactics:    tactics,
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

	// Get mitigation external ID and name
	chosenMit := mitMap[chosenMitSTIXID]
	mitExt, _ := externalID(chosenMit.ExternalRefs)

	if *flagExecute {
		// Execute mode - run INSERT statements against database
		cfg := getNebulaConfig()
		if *flagDbg {
			fmt.Fprintf(os.Stderr, ">>> Connecting to Nebula Graph at %s:%d\n", cfg.Host, cfg.Port)
		}

		session, cleanup, err := connectNebula(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error connecting to Nebula Graph: %v\n", err)
			os.Exit(1)
		}
		defer cleanup()

		// Check if mitigation exists
		exists, err := checkMitigationExists(session, mitExt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error checking mitigation: %v\n", err)
			os.Exit(1)
		}

		if !exists {
			fmt.Fprintf(os.Stderr, "ERROR: Mitigation %s does not exist in database.\n", mitExt)
			fmt.Fprintf(os.Stderr, "You must create it first with:\n")
			fmt.Fprintf(os.Stderr, "INSERT VERTEX IF NOT EXISTS tMitreMitigation(Mitigation_ID, Mitigation_Name, Matrix, Description, Mitigation_Version) VALUES \"%s\":(\"%s\", %s, \"Enterprise\", \"...\", \"...\");\n\n",
				mitExt, mitExt, quoteLiteral(chosenMit.Name))
			os.Exit(1)
		}

		// Find missing techniques
		allTechIDs := make([]string, len(results))
		for i, t := range results {
			allTechIDs[i] = t.ExternalID
		}

		missingTechniques, err := findMissingTechniques(session, allTechIDs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error checking techniques: %v\n", err)
			os.Exit(1)
		}

		if *flagDbg {
			fmt.Fprintf(os.Stderr, ">>> Total techniques: %d\n", len(allTechIDs))
			fmt.Fprintf(os.Stderr, ">>> Missing techniques: %d\n", len(missingTechniques))
		}

		// Execute statements
		if err := executeNGQL(session, mitExt, chosenMit.Name, results, missingTechniques); err != nil {
			fmt.Fprintf(os.Stderr, "execution failed: %v\n", err)
			os.Exit(1)
		}

		return
	}

	if *flagNGQL {
		// Enhanced nGQL generation with database check
		if *flagNoDB {
			// Generate nGQL without database check (assume all missing)
			allTechIDs := make([]string, len(results))
			for i, t := range results {
				allTechIDs[i] = t.ExternalID
			}
			script := generateNGQL(mitExt, chosenMit.Name, results, allTechIDs)
			fmt.Print(script)
		} else {
			// Connect to database and check for missing techniques
			cfg := getNebulaConfig()
			if *flagDbg {
				fmt.Fprintf(os.Stderr, ">>> Connecting to Nebula Graph at %s:%d\n", cfg.Host, cfg.Port)
			}

			session, cleanup, err := connectNebula(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error connecting to Nebula Graph: %v\n", err)
				os.Exit(1)
			}
			defer cleanup()

			// Check if mitigation exists
			exists, err := checkMitigationExists(session, mitExt)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error checking mitigation: %v\n", err)
				os.Exit(1)
			}

			if !exists {
				fmt.Fprintf(os.Stderr, "WARNING: Mitigation %s does not exist in database.\n", mitExt)
				fmt.Fprintf(os.Stderr, "You may need to create it first with:\n")
				fmt.Fprintf(os.Stderr, "INSERT VERTEX IF NOT EXISTS tMitreMitigation(Mitigation_ID, Mitigation_Name, Matrix, Description, Mitigation_Version) VALUES \"%s\":(\"%s\", %s, \"Enterprise\", \"...\", \"...\");\n\n",
					mitExt, mitExt, quoteLiteral(chosenMit.Name))
			}

			// Find missing techniques
			allTechIDs := make([]string, len(results))
			for i, t := range results {
				allTechIDs[i] = t.ExternalID
			}

			missingTechniques, err := findMissingTechniques(session, allTechIDs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error checking techniques: %v\n", err)
				os.Exit(1)
			}

			if *flagDbg {
				fmt.Fprintf(os.Stderr, ">>> Total techniques: %d\n", len(allTechIDs))
				fmt.Fprintf(os.Stderr, ">>> Missing techniques: %d\n", len(missingTechniques))
			}

			script := generateNGQL(mitExt, chosenMit.Name, results, missingTechniques)
			fmt.Print(script)
		}
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
		_ = w.Write([]string{"Mitigation ID", "Mitigation Name", "Technique ID", "Technique Name", "Tactics"})
		for _, t := range results {
			_ = w.Write([]string{mitExt, chosenMit.Name, t.ExternalID, t.Name, strings.Join(t.Tactics, "; ")})
		}
		w.Flush()
		return
	}

	// default: pretty table
	printTable(chosenMitSTIXID, chosenMit, results, len(mitMap))
}

/*
-------------------------------------------------------------
Pretty-print table (default output)
-------------------------------------------------------------
*/
func printTable(mitSTIX string, mit courseOfAction, data []techniqueInfo, totalMitigations int) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	mitExt, _ := externalID(mit.ExternalRefs)

	fmt.Fprintf(w, "MITIGATION\t%s (%s)\n", mit.Name, mitExt)
	fmt.Fprintf(w, "ACTIVE MITIGATIONS\t%d Enterprise mitigations (all others filtered out)\n", totalMitigations)
	fmt.Fprintln(w, "---------------------------------------------------------------")
	fmt.Fprintln(w, "TECHNIQUE ID\tTECHNIQUE NAME\tTACTICS")

	for _, t := range data {
		tactics := strings.Join(t.Tactics, ", ")
		fmt.Fprintf(w, "%s\t%s\t%s\n", t.ExternalID, t.Name, tactics)
	}

	_ = w.Flush()
}
