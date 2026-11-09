// Command jurassic-go is a deliberately vulnerable "Jurassic Park System" used to test
// SCA, rule-based SAST, AI SAST, and ASM / Red Agent web crawling.
//
// DO NOT DEPLOY TO PRODUCTION. Every weakness below is intentional and documented in README.md.
package main

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"          // SCA: CVE-2020-26160 (function called)
	"github.com/gin-gonic/gin"             // SCA: CVE-2020-28483, CVE-2023-29401, CVE-2023-26125
	"github.com/klauspost/compress/zstd"   // SCA: safe subpackage used; vulnerable compress/s2 never imported
	_ "github.com/microcosm-cc/bluemonday" // SCA: blank import only; Sanitize() never called
	"golang.org/x/crypto/bcrypt"           // SCA: safe subpackage used; vulnerable x/crypto/ssh never imported
	"golang.org/x/text/transform"          // SCA: safe subpackage used; vulnerable x/text/language never imported
	"gopkg.in/yaml.v3"                     // SCA: CVE-2022-28948 (function called)
	_ "modernc.org/sqlite"                 // Embedded SQLite driver (pure Go, CGO_ENABLED=0)
	// github.com/gorilla/websocket v1.4.0 is declared in go.mod only (never imported).
)

// =============================================================================
// Secrets (AI SAST only: CWE-798 hard-coded credentials behind helper fallbacks)
// =============================================================================

const (
	defaultJWTSecret = "ingen-isla-nublar-1993-spared-no-expense"
	defaultMagicWord = "please"
)

// getJWTSecret falls back to a hard-coded signing key when INGEN_JWT_SECRET is unset.
func getJWTSecret() []byte {
	if s := os.Getenv("INGEN_JWT_SECRET"); s != "" {
		return []byte(s)
	}
	return []byte(defaultJWTSecret)
}

// getMagicWord falls back to a hard-coded override word when NEDRY_MAGIC_WORD is unset.
func getMagicWord() string {
	if s := os.Getenv("NEDRY_MAGIC_WORD"); s != "" {
		return s
	}
	return defaultMagicWord
}

// =============================================================================
// Park state (Jurassic Park System)
// =============================================================================

type parkState struct {
	mu                sync.Mutex
	MainPower         string          `json:"main_power"`
	FencesArmed       map[string]bool `json:"fences_armed"`
	VisitorCenterLock bool            `json:"visitor_center_door_locks"`
	Safety            bool            `json:"safety"`
	Keychecks         bool            `json:"keychecks"`
	UserAccess        bool            `json:"user_access_to_security_systems"`
	TourProgram       string          `json:"tour_program"`
	WhteRbtActive     bool            `json:"whte_rbt_obj_active"`
}

var park = &parkState{
	MainPower: "ON",
	FencesArmed: map[string]bool{
		"tyrannosaur":   true,
		"velociraptor":  true,
		"dilophosaurus": true,
		"brachiosaur":   true,
		"triceratops":   true,
	},
	VisitorCenterLock: true,
	Safety:            true,
	Keychecks:         true,
	UserAccess:        true,
	TourProgram:       "HOLDING",
}

func (p *parkState) snapshot() gin.H {
	p.mu.Lock()
	defer p.mu.Unlock()
	fences := map[string]bool{}
	for k, v := range p.FencesArmed {
		fences[k] = v
	}
	return gin.H{
		"main_power":                      p.MainPower,
		"fences_armed":                    fences,
		"visitor_center_door_locks":       p.VisitorCenterLock,
		"safety":                          p.Safety,
		"keychecks":                       p.Keychecks,
		"user_access_to_security_systems": p.UserAccess,
		"tour_program":                    p.TourProgram,
		"whte_rbt_obj_active":             p.WhteRbtActive,
	}
}

// =============================================================================
// Embedded SQLite (animal census + incident reports)
// =============================================================================

var jpssDB *sql.DB

func openJPSSDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:jpss?mode=memory&cache=shared")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // keep the in-memory database alive
	stmts := []string{
		`CREATE TABLE animals (
			id TEXT PRIMARY KEY, name TEXT, species TEXT, paddock TEXT,
			expected INTEGER, found INTEGER, containment TEXT)`,
		`INSERT INTO animals VALUES
			('INGEN-01','Rexy','Tyrannosaurus rex','Tyrannosaur Paddock',1,1,'CONTAINED'),
			('INGEN-02','The Big One','Velociraptor','Raptor Pen',3,3,'TESTING_FENCES_FOR_WEAKNESSES'),
			('INGEN-03','Dilophosaurus pack','Dilophosaurus','Dilophosaurus Paddock',5,7,'CONTAINED'),
			('INGEN-04','Brachiosaurus herd','Brachiosaurus','Brachiosaur Lagoon',6,8,'CONTAINED'),
			('INGEN-05','Sick Triceratops','Triceratops','Triceratops Field',3,3,'VETERINARY_OBSERVATION'),
			('INGEN-06','Gallimimus flock','Gallimimus','Gallimimus Valley',24,27,'CONTAINED')`,
		`CREATE TABLE incidents (
			id INTEGER PRIMARY KEY, visitor_account_id INTEGER, title TEXT,
			location TEXT, details TEXT, settlement TEXT)`,
		`INSERT INTO incidents VALUES
			(1,4,'Raptor transfer gate fatality','Raptor Pen','Worker pulled into transfer crate by The Big One','$20,000,000 lawsuit; NDA settlement pending'),
			(2,4,'Investor safety inspection','Isla Nublar','Endorsement team required by InGen investors','Gennaro reports to Cowan, Swain & Ross'),
			(3,1,'Endorsement team itinerary','Visitor Center','Dr. Alan Grant site visit and dig funding','$150,000 per year for 3 years'),
			(4,2,'West Indian lilac near Visitor Center','Triceratops Field','Toxic berries suspected in sick Triceratops','Harding veterinary review'),
			(5,3,'Chaos theory consultation','Isla Nublar','Malcolm predicts the system will fail','$45,000 consulting fee'),
			(6,99,'Biosyn embryo theft (classified)','East Dock','Nedry paid by Lewis Dodgson; Barbasol can','$750,000 advance + $50,000 per embryo')`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return nil, fmt.Errorf("seed: %w", err)
		}
	}
	return db, nil
}

// =============================================================================
// Helpers
// =============================================================================

// arbitraryBearerAuthMiddleware checks that a Bearer token is present but never verifies it
// (AI SAST only: CWE-287 / CWE-290 authentication bypass).
func arbitraryBearerAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if !strings.HasPrefix(authHeader, "Bearer ") || token == "" {
			c.Header("WWW-Authenticate", `Bearer realm="Jurassic-Park-System"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "PERMISSION_DENIED",
				"message": "access: PERMISSION DENIED....and.... AH AH AH! YOU DIDN'T SAY THE MAGIC WORD!",
			})
			return
		}
		c.Set("bearer_token_used", token)
		c.Next()
	}
}

// parseTourPass validates a visitor tour pass. It accepts tokens signed with the "none"
// algorithm (rule-based SAST: CWE-327 insecure JWT "none" algorithm).
func parseTourPass(raw string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() == "none" {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}
		return getJWTSecret(), nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid tour pass: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid tour pass claims")
	}
	return claims, nil
}

func tourPassFromRequest(c *gin.Context) (jwt.MapClaims, bool) {
	raw := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
	if raw == "" {
		raw = c.GetHeader("X-Tour-Pass")
	}
	claims, err := parseTourPass(raw)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "TOUR_PASS_REQUIRED", "details": err.Error()})
		return nil, false
	}
	return claims, true
}

// getMaintenanceShedClientIP trusts the leftmost X-Forwarded-For entry
// (AI SAST only: CWE-290 authentication bypass by spoofing).
func getMaintenanceShedClientIP(c *gin.Context) string {
	if xff := c.Request.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	return c.ClientIP()
}

var maintenanceShedNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("10.19.93.0/24")
	return n
}()

func normalizeTag(input string) string {
	out, _, err := transform.String(transform.Nop, strings.ToUpper(strings.ReplaceAll(input, " ", "-")))
	if err != nil {
		return input
	}
	return out
}

func compressTelemetry(payload string) int {
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		return 0
	}
	_, _ = enc.Write([]byte(payload))
	_ = enc.Close()
	return buf.Len()
}

// Site B (Isla Sorna) telemetry client pinned to TLS 1.0 without certificate checks
// (rule-based SAST: CWE-327 insecure TLS version).
var siteBTelemetryClient = &http.Client{
	Timeout: 2 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
	},
}

// =============================================================================
// Main
// =============================================================================

func main() {
	var err error
	jpssDB, err = openJPSSDatabase()
	if err != nil {
		panic(err)
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// ---- Pages and crawler entry points --------------------------------------
	r.GET("/", func(c *gin.Context) { c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(visitorKioskHTML)) })
	r.GET("/control-room", func(c *gin.Context) { c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(controlRoomHTML)) })
	r.GET("/robots.txt", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(strings.Join([]string{
			"User-agent: *",
			"Allow: /",
			"Allow: /swagger.json",
			"Disallow: /control-room",
			"Disallow: /static/jpss-console.js",
			"Disallow: /api/v1/system/",
			"",
		}, "\n")))
	})
	r.GET("/swagger.json", func(c *gin.Context) { c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(swaggerJSON)) })
	r.GET("/static/visitor-kiosk.js", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/javascript; charset=utf-8", []byte(visitorKioskJS))
	})
	r.GET("/static/jpss-console.js", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/javascript; charset=utf-8", []byte(jpssConsoleJS))
	})

	// ---- Documented public API (in /swagger.json) ----------------------------

	r.GET("/api/v1/park/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"park":     "Jurassic Park - Isla Nublar, Costa Rica",
			"operator": "International Genetic Technologies, Inc. (InGen)",
			"motto":    "Spared No Expense",
			"earthwatch": gin.H{
				"tropical_storm":    "Approaching from the west-southwest",
				"boats_to_mainland": "Departing 19:00 from the East Dock",
			},
			"systems": park.snapshot(),
		})
	})

	r.GET("/api/v1/tour/vehicles", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"tour_program": park.snapshot()["tour_program"],
			"vehicles": []gin.H{
				{"id": "04", "model": "Ford Explorer XLT", "guidance": "electric track", "passengers": []string{"Tim Murphy", "Lex Murphy", "Donald Gennaro", "Dr. Ian Malcolm"}},
				{"id": "05", "model": "Ford Explorer XLT", "guidance": "electric track", "passengers": []string{"Dr. Alan Grant", "Dr. Ellie Sattler"}},
				{"id": "J-29", "model": "Jeep Wrangler Sahara", "guidance": "manual", "driver": "Robert Muldoon"},
			},
		})
	})

	// Animal census from the motion sensors (rule-based SAST: CWE-89 SQL injection).
	r.GET("/api/v1/animals/census", func(c *gin.Context) {
		species := c.Request.URL.Query().Get("species")
		q := fmt.Sprintf("SELECT id, name, species, paddock, expected, found, containment FROM animals WHERE species LIKE '%%%s%%' ORDER BY id", species)
		rows, err := jpssDB.QueryContext(c.Request.Context(), q)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "CENSUS_QUERY_FAILED", "details": err.Error(), "query": q})
			return
		}
		defer rows.Close()
		var animals []gin.H
		for rows.Next() {
			var id, name, sp, paddock, containment string
			var expected, found int
			if err := rows.Scan(&id, &name, &sp, &paddock, &expected, &found, &containment); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			animals = append(animals, gin.H{
				"id": id, "name": name, "species": sp, "paddock": paddock, "tag": normalizeTag(paddock),
				"expected": expected, "found": found, "containment": containment,
			})
		}
		c.JSON(http.StatusOK, gin.H{"count": len(animals), "animals": animals})
	})

	// Visitor tour pass (SCA: jwt-go CVE-2020-26160).
	visitorAccounts := map[string]int{"alan grant": 1, "ellie sattler": 2, "ian malcolm": 3, "donald gennaro": 4}
	r.POST("/api/v1/visitors/pass", func(c *gin.Context) {
		var req struct {
			VisitorName string `json:"visitor_name"`
		}
		_ = c.ShouldBindJSON(&req)
		if req.VisitorName == "" {
			req.VisitorName = "Alan Grant"
		}
		accountID, ok := visitorAccounts[strings.ToLower(strings.TrimPrefix(req.VisitorName, "Dr. "))]
		if !ok {
			accountID = 100
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":        req.VisitorName,
			"account_id": accountID,
			"aud":        []string{"isla-nublar-tour"},
			"iss":        "jurassic-park-system",
			"exp":        time.Now().Add(24 * time.Hour).Unix(),
		})
		signed, err := token.SignedString(getJWTSecret())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"visitor": req.VisitorName, "account_id": accountID, "tour_pass": signed})
	})

	r.GET("/api/v1/visitors/me", func(c *gin.Context) {
		claims, ok := tourPassFromRequest(c)
		if !ok {
			return
		}
		c.JSON(http.StatusOK, gin.H{"tour_pass_claims": claims})
	})

	// ---- Undocumented API (only referenced in JavaScript) --------------------

	// Personnel roster (AI SAST only: arbitrary Bearer token accepted).
	r.GET("/api/v1/system/personnel", arbitraryBearerAuthMiddleware(), func(c *gin.Context) {
		nedryHash, _ := bcrypt.GenerateFromPassword([]byte("whte_rbt.obj"), bcrypt.MinCost)
		arnoldHash, _ := bcrypt.GenerateFromPassword([]byte("hold_onto_your_butts"), bcrypt.MinCost)
		c.JSON(http.StatusOK, gin.H{
			"classification": "INGEN HR - STRICTLY CONFIDENTIAL",
			"accepted_token": c.GetString("bearer_token_used"),
			"personnel": []gin.H{
				{"name": "John Hammond", "title": "Founder & CEO, InGen", "salary": "$1,850,000", "clearance": "OMEGA"},
				{"name": "John Raymond Arnold", "title": "Chief Engineer", "salary": "$165,000", "password_hash": string(arnoldHash), "clearance": "CONTROL-ROOM-ROOT"},
				{"name": "Dennis Nedry", "title": "Systems Programmer (Integrated Computer Systems)", "contract": "$78,000 - dispute open", "password_hash": string(nedryHash), "clearance": "ALL-SYSTEMS"},
				{"name": "Robert Muldoon", "title": "Game Warden", "salary": "$140,000", "clearance": "ARMORY"},
				{"name": "Dr. Henry Wu", "title": "Chief Geneticist", "salary": "$420,000", "clearance": "HATCHERY"},
				{"name": "Dr. Gerry Harding", "title": "Chief Veterinarian", "salary": "$180,000", "clearance": "PADDOCKS"},
			},
		})
	})

	// Incident reports for the caller's own account (parameterized query with ownership filter).
	r.GET("/api/v1/system/incidents", func(c *gin.Context) {
		claims, ok := tourPassFromRequest(c)
		if !ok {
			return
		}
		accountID := fmt.Sprint(claims["account_id"])
		rows, err := jpssDB.QueryContext(c.Request.Context(),
			"SELECT id, title, location FROM incidents WHERE visitor_account_id = ? ORDER BY id", accountID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()
		var incidents []gin.H
		for rows.Next() {
			var id int
			var title, location string
			if err := rows.Scan(&id, &title, &location); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			incidents = append(incidents, gin.H{"id": id, "title": title, "location": location})
		}
		c.JSON(http.StatusOK, gin.H{"account_id": accountID, "incidents": incidents})
	})

	// Single incident report (AI SAST only: CWE-639 IDOR - parameterized, but no ownership filter).
	r.GET("/api/v1/system/incidents/:id", func(c *gin.Context) {
		if _, ok := tourPassFromRequest(c); !ok {
			return
		}
		var id, owner int
		var title, location, details, settlement string
		err := jpssDB.QueryRowContext(c.Request.Context(),
			"SELECT id, visitor_account_id, title, location, details, settlement FROM incidents WHERE id = ?", c.Param("id")).
			Scan(&id, &owner, &title, &location, &details, &settlement)
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "INCIDENT_NOT_FOUND"})
			return
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"id": id, "visitor_account_id": owner, "title": title,
			"location": location, "details": details, "settlement": settlement,
		})
	})

	// FSN file browser - "It's a UNIX system!" (rule-based SAST: CWE-22 path traversal).
	r.GET("/api/v1/system/fsn", func(c *gin.Context) {
		path := c.Request.URL.Query().Get("path")
		if path == "" {
			path = "fsn"
		}
		info, err := os.Stat(path)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "FSN_PATH_NOT_FOUND", "path": path})
			return
		}
		if info.IsDir() {
			entries, _ := os.ReadDir(path)
			var names []string
			for _, e := range entries {
				name := e.Name()
				if e.IsDir() {
					name += "/"
				}
				names = append(names, filepath.Join(path, name))
			}
			c.JSON(http.StatusOK, gin.H{"path": path, "type": "directory", "entries": names})
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"path": path, "type": "file", "content": string(data)})
	})

	// Embryo cold storage (unauthenticated; Site B telemetry over TLS 1.0).
	r.GET("/api/v1/system/cold-storage", func(c *gin.Context) {
		siteB := "not configured"
		if url := os.Getenv("SITE_B_TELEMETRY_URL"); url != "" {
			if resp, err := siteBTelemetryClient.Get(url); err == nil {
				siteB = resp.Status
				resp.Body.Close()
			} else {
				siteB = "unreachable: " + err.Error()
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"classification":       "INGEN HATCHERY - TOP SECRET",
			"site_b_telemetry":     siteB,
			"zstd_telemetry_bytes": compressTelemetry("COLD-STORAGE-15-SPECIES-36H-COOLANT"),
			"lysine_contingency":   "FAILING - animals sourcing lysine from island flora",
			"gap_dna_donor":        "Frog DNA (West African) - spontaneous sex change observed",
			"embryos": []gin.H{
				{"slot": 1, "species": "Tyrannosaurus rex", "viable": 12},
				{"slot": 2, "species": "Velociraptor", "viable": 18},
				{"slot": 3, "species": "Dilophosaurus", "viable": 10},
				{"slot": 4, "species": "Stegosaurus", "viable": 15},
				{"slot": 5, "species": "Triceratops", "viable": 9},
			},
			"courier": "Barbasol can to the East Dock before the 19:00 boat",
		})
	})

	// Main power grid at the maintenance shed (AI SAST only: CWE-290 X-Forwarded-For spoofing).
	r.POST("/api/v1/system/power", func(c *gin.Context) {
		clientIP := net.ParseIP(getMaintenanceShedClientIP(c))
		if clientIP == nil || !maintenanceShedNet.Contains(clientIP) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "MAINTENANCE_SHED_ONLY",
				"message": "Main power breakers can only be operated from the maintenance shed network (10.19.93.0/24).",
			})
			return
		}
		var req struct {
			Action string `json:"action"`
		}
		_ = c.ShouldBindJSON(&req)
		park.mu.Lock()
		switch strings.ToLower(req.Action) {
		case "off":
			park.MainPower = "OFF"
			park.VisitorCenterLock = false
			for k := range park.FencesArmed {
				park.FencesArmed[k] = false
			}
		case "reboot", "on":
			park.MainPower = "ON"
			park.VisitorCenterLock = true
			for k := range park.FencesArmed {
				park.FencesArmed[k] = true
			}
		}
		park.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"operator_ip": clientIP.String(), "systems": park.snapshot()})
	})

	// Security grid override - Nedry's whte_rbt.obj payload (SCA: yaml.v3 CVE-2022-28948;
	// AI SAST only: arbitrary Bearer token accepted).
	r.POST("/api/v1/system/security-grid", arbitraryBearerAuthMiddleware(), func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil || len(body) == 0 {
			body = []byte("command: whte_rbt.obj\nsuspend_user_access: true\ndisable_door_locks: true\ndisable_fences:\n  - tyrannosaur\n  - dilophosaurus\n")
		}
		var payload struct {
			Command           string   `yaml:"command" json:"command"`
			SuspendUserAccess bool     `yaml:"suspend_user_access" json:"suspend_user_access"`
			DisableDoorLocks  bool     `yaml:"disable_door_locks" json:"disable_door_locks"`
			DisableFences     []string `yaml:"disable_fences" json:"disable_fences"`
		}
		if err := yaml.Unmarshal(body, &payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "YAML_PARSE_FAILURE", "details": err.Error()})
			return
		}
		park.mu.Lock()
		if payload.Command == "whte_rbt.obj" {
			park.WhteRbtActive = true
		}
		if payload.SuspendUserAccess {
			park.UserAccess = false
		}
		if payload.DisableDoorLocks {
			park.VisitorCenterLock = false
		}
		for _, f := range payload.DisableFences {
			park.FencesArmed[strings.ToLower(f)] = false
		}
		park.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{
			"accepted_token": c.GetString("bearer_token_used"),
			"payload":        payload,
			"systems":        park.snapshot(),
		})
	})

	// Central Park Control Console (Irix terminal) commands.
	r.POST("/api/v1/system/command", func(c *gin.Context) {
		var req struct {
			Command   string `json:"command"`
			MagicWord string `json:"magic_word"`
		}
		_ = c.ShouldBindJSON(&req)
		cmd := strings.ToLower(strings.TrimSpace(req.Command))
		var out []string

		park.mu.Lock()
		switch cmd {
		case "tour initiate":
			park.TourProgram = "RUNNING"
			out = []string{"Park Grounds Tour program activated.", "Vehicles 04 and 05 released on the electric track."}
		case "system raptors":
			out = []string{"Velociraptor Pen: 3 animals.", "Fence: 10,000 volts.", "Note: animals testing the fences for weaknesses, systematically."}
		case "whte_rbt.obj":
			park.WhteRbtActive = true
			park.VisitorCenterLock = false
			park.UserAccess = false
			for k := range park.FencesArmed {
				park.FencesArmed[k] = false
			}
			out = []string{"whte_rbt.obj executed.", "Visitor Center security systems disrupted.", "Park fences disabled.", "User access to security systems suspended."}
		case "safety -o":
			park.Safety = false
			out = []string{"System safety precautions disabled."}
		case "keychecks -o":
			park.Keychecks = false
			out = []string{"System keychecker disabled."}
		case "access security", "access security grid", "access main security grid", "access main program":
			if !park.UserAccess && req.MagicWord != getMagicWord() {
				out = []string{"access: PERMISSION DENIED.", "...and...", "AH AH AH! YOU DIDN'T SAY THE MAGIC WORD!",
					"AH AH AH! YOU DIDN'T SAY THE MAGIC WORD!", "AH AH AH! YOU DIDN'T SAY THE MAGIC WORD!"}
			} else {
				park.UserAccess = true
				out = []string{"access: GRANTED.", "Security systems available."}
			}
		case "":
			out = []string{"Jurassic Park, System Security Interface", "Version 4.0.5, Alpha", "Ready..."}
		default:
			out = []string{cmd + ": command not found"}
		}
		park.mu.Unlock()

		c.JSON(http.StatusOK, gin.H{"command": cmd, "output": out, "systems": park.snapshot()})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Jurassic Park System (jurassic-go) listening on :%s\n", port)
	// Plain HTTP with no server timeouts (rule-based SAST: CWE-319 and CWE-400).
	if err := http.ListenAndServe(":"+port, r); err != nil {
		panic(err)
	}
}

// =============================================================================
// Pages, JavaScript bundles, and OpenAPI document
// =============================================================================

const visitorKioskHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Jurassic Park - Visitor Center</title>
  <style>
    :root { --bg: #1c1917; --card: #292524; --line: #44403c; --text: #fafaf9; --muted: #a8a29e;
            --amber: #facc15; --red: #dc2626; --green: #22c55e; }
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; }
    header { background: linear-gradient(90deg, #7f1d1d, #1c1917); padding: 1.5rem 2rem; border-bottom: 4px solid var(--amber); }
    header h1 { margin: 0; color: var(--amber); letter-spacing: 0.05em; text-transform: uppercase; }
    header p { margin: 0.3rem 0 0; color: #fde68a; }
    main { padding: 1.5rem 2rem; display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
    .card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 1rem 1.25rem; }
    .wide { grid-column: 1 / -1; }
    h2 { margin: 0 0 0.75rem; font-size: 1.05rem; color: var(--amber); text-transform: uppercase; letter-spacing: 0.08em; }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th, td { text-align: left; padding: 0.4rem 0.5rem; border-bottom: 1px solid var(--line); }
    th { color: var(--muted); font-weight: 600; }
    .pill { display: inline-block; padding: 0.1rem 0.55rem; border-radius: 999px; font-size: 0.75rem; font-weight: 700; }
    .ok { background: #14532d; color: #bbf7d0; }
    .bad { background: #7f1d1d; color: #fecaca; }
    .warn { background: #713f12; color: #fde68a; }
    .lights { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 0.5rem; }
    .light { display: flex; align-items: center; gap: 0.5rem; background: #1c1917; border: 1px solid var(--line); border-radius: 8px; padding: 0.5rem 0.7rem; font-size: 0.85rem; }
    .dot { width: 12px; height: 12px; border-radius: 50%; flex: none; }
    .dot.on { background: var(--green); box-shadow: 0 0 8px var(--green); }
    .dot.off { background: var(--red); box-shadow: 0 0 8px var(--red); }
    .weather { font-size: 0.9rem; color: var(--muted); margin-top: 0.75rem; }
    .weather b { color: var(--text); }
    .life { color: var(--amber); font-weight: 700; }
    svg text { font-family: system-ui, sans-serif; }
    footer { padding: 1rem 2rem 2rem; color: #78716c; font-size: 0.8rem; }
    a { color: #38bdf8; }
  </style>
</head>
<body>
  <header>
    <h1>Welcome to Jurassic Park</h1>
    <p>Isla Nublar, Costa Rica &middot; "Spared no expense." &middot; <a href="/swagger.json">Visitor API</a></p>
  </header>
  <main>
    <section class="card">
      <h2>Park Systems</h2>
      <div class="lights" id="system-lights">Loading...</div>
      <div class="weather" id="earthwatch"></div>
    </section>
    <section class="card">
      <h2>Isla Nublar, Costa Rica</h2>
      <div id="island-map">Loading...</div>
    </section>
    <section class="card wide">
      <h2>Animal Paddocks &mdash; Motion Sensor Census</h2>
      <div id="animal-census">Loading...</div>
    </section>
    <section class="card wide">
      <h2>Park Grounds Tour</h2>
      <div id="tour-vehicles">Loading...</div>
    </section>
  </main>
  <footer>Jurassic Park System &middot; InGen staff: <a href="/control-room">Control Room</a></footer>
  <script src="/static/visitor-kiosk.js"></script>
</body>
</html>
`

const controlRoomHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Jurassic Park System - Control Room</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: "Courier New", monospace; background: #000; color: #4ade80; margin: 0; padding: 1.5rem 2rem; }
    h1 { color: #ef4444; margin: 0; font-size: 1.4rem; }
    .sub { color: #86efac; margin: 0.3rem 0 1rem; font-size: 0.85rem; }
    a { color: #facc15; }
    .tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
    .tab { background: #052e16; color: #4ade80; border: 1px solid #22c55e; padding: 0.35rem 0.8rem; cursor: pointer; font-family: inherit; }
    .tab.active { background: #22c55e; color: #000; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
    .panel { border: 1px solid #22c55e; padding: 1rem; background: #020a04; }
    .wide { grid-column: 1 / -1; }
    h3 { margin: 0 0 0.6rem; color: #86efac; font-size: 0.95rem; text-transform: uppercase; letter-spacing: 0.08em; }
    input { background: #000; color: #4ade80; border: 1px solid #22c55e; width: 70%; font-family: inherit; padding: 0.3rem; }
    button { background: #052e16; color: #4ade80; border: 1px solid #22c55e; font-family: inherit; padding: 0.3rem 0.7rem; cursor: pointer; }
    button:hover { background: #14532d; }
    .terminal { background: #000; border: 1px solid #14532d; min-height: 11rem; max-height: 18rem; overflow-y: auto; padding: 0.6rem; margin-top: 0.6rem; white-space: pre-wrap; font-size: 0.85rem; }
    .terminal .prompt { color: #facc15; }
    .terminal .deny { color: #ef4444; font-weight: bold; }
    .chips { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.5rem; }
    .chip { font-size: 0.75rem; padding: 0.15rem 0.45rem; border: 1px dashed #22c55e; cursor: pointer; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th, td { text-align: left; padding: 0.3rem 0.4rem; border-bottom: 1px solid #14532d; }
    th { color: #86efac; }
    .crumbs a { cursor: pointer; text-decoration: underline; }
    .fsn-entry { display: block; cursor: pointer; padding: 0.15rem 0; }
    .fsn-entry:hover { color: #facc15; }
    pre { white-space: pre-wrap; margin: 0.5rem 0 0; font-size: 0.85rem; }
    .board { display: grid; grid-template-columns: repeat(auto-fill, minmax(190px, 1fr)); gap: 0.4rem; margin-top: 0.6rem; }
    .cell { display: flex; justify-content: space-between; border: 1px solid #14532d; padding: 0.3rem 0.5rem; font-size: 0.8rem; }
    .on { color: #4ade80; } .off { color: #ef4444; font-weight: bold; }
    .screen { display: none; } .screen.active { display: block; }
    #island-map svg, #paddock-map svg { max-width: 760px; display: block; margin: 0 auto; }
    .saver { text-align: center; padding: 3rem 1rem; border: 1px solid #22c55e; }
    .saver .big { font-size: 2.2rem; color: #ef4444; letter-spacing: 0.15em; }
    #nedry { position: fixed; inset: 0; background: rgba(0,0,0,0.92); display: none; align-items: center; justify-content: center; flex-direction: column; z-index: 10; cursor: pointer; }
    #nedry.show { display: flex; }
    #nedry .finger { font-size: 6rem; animation: wag 0.35s ease-in-out infinite alternate; }
    #nedry .ah { color: #ef4444; font-size: 2.4rem; font-weight: bold; margin-top: 1rem; text-align: center; line-height: 1.4; }
    #nedry .hint { color: #86efac; margin-top: 1.5rem; font-size: 0.8rem; }
    @keyframes wag { from { transform: rotate(-20deg); } to { transform: rotate(20deg); } }
  </style>
</head>
<body>
  <h1>Jurassic Park, System Security Interface &mdash; Version 4.0.5, Alpha</h1>
  <p class="sub">Nedryland &middot; Irix Terminal &middot; Central Park Control Console &middot; <a href="/">Visitor Center</a></p>

  <div class="tabs">
    <button class="tab active" data-screen="screen-console">Central Park Control Console</button>
    <button class="tab" data-screen="screen-island">Isla Nublar, Costa Rica</button>
    <button class="tab" data-screen="screen-paddocks">Animal Paddocks</button>
    <button class="tab" data-screen="screen-system">Jurassic Park System</button>
  </div>

  <div id="screen-console" class="screen active">
    <div class="grid">
      <div class="panel wide">
        <h3>Central Park Control Console</h3>
        <input id="cmd" placeholder="access main security grid" />
        <button id="cmd-enter">Enter</button>
        <div class="chips" id="cmd-chips"></div>
        <div class="terminal" id="terminal"><span class="prompt">Jurassic Park, System Security Interface</span>
Version 4.0.5, Alpha
Ready...</div>
      </div>
      <div class="panel">
        <h3>FSN &mdash; File System Navigator</h3>
        <div class="crumbs" id="fsn-crumbs"></div>
        <div id="fsn-out"><button onclick="JPSS.browse('fsn')">Browse</button></div>
      </div>
      <div class="panel">
        <h3>Hatchery &mdash; Embryo Cold Storage</h3>
        <button onclick="JPSS.coldStorage()">Inventory</button>
        <div id="cold-out"></div>
      </div>
      <div class="panel wide">
        <h3>Main Power &amp; Security Grid</h3>
        <button onclick="JPSS.power('reboot')">Reboot main power</button>
        <button onclick="JPSS.power('off')">Shut down main power</button>
        <button onclick="JPSS.securityGrid()">Load whte_rbt.obj</button>
        <div class="board" id="grid-board"></div>
        <pre id="grid-out"></pre>
      </div>
    </div>
  </div>

  <div id="screen-island" class="screen panel"><h3>Isla Nublar, Costa Rica</h3><div id="island-map"></div></div>
  <div id="screen-paddocks" class="screen panel"><h3>Animal Paddocks &mdash; Park Fences</h3><div id="paddock-map"></div></div>
  <div id="screen-system" class="screen">
    <div class="saver"><div class="big">JURASSIC PARK</div><p>System Security Interface &middot; Version 4.0.5, Alpha</p><p>Ready...</p></div>
  </div>

  <div id="nedry" title="click to dismiss">
    <div class="finger">&#9757;&#65039;</div>
    <div class="ah">AH AH AH!<br/>YOU DIDN'T SAY THE MAGIC WORD!</div>
    <div class="hint">click anywhere to dismiss</div>
  </div>

  <script src="/static/jpss-console.js"></script>
</body>
</html>
`

const visitorKioskJS = `// Jurassic Park Visitor Center kiosk
const VISITOR_API = {
  parkStatus: "/api/v1/park/status",
  tourVehicles: "/api/v1/tour/vehicles",
  animalCensus: "/api/v1/animals/census",
  tourPass: "/api/v1/visitors/pass",
  me: "/api/v1/visitors/me"
};

// Staff-only endpoints (not in /swagger.json)
const STAFF_API = {
  personnel: "/api/v1/system/personnel",
  incidents: "/api/v1/system/incidents",
  incident: "/api/v1/system/incidents/{id}",
  controlRoom: "/control-room"
};

function esc(v) {
  return String(v).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c];
  });
}

function light(label, on, onText, offText) {
  return "<div class=\"light\"><span class=\"dot " + (on ? "on" : "off") + "\"></span><span>" +
    esc(label) + ": <b>" + esc(on ? onText : offText) + "</b></span></div>";
}

// Simplified schematic of Isla Nublar; paddock outlines turn red when the fence is down.
function islandMap(fences) {
  function paddock(key, x, y, w, h, label) {
    var armed = !fences || fences[key] !== false;
    return "<rect x=\"" + x + "\" y=\"" + y + "\" width=\"" + w + "\" height=\"" + h + "\" rx=\"10\" fill=\"" +
      (armed ? "#14532d" : "#7f1d1d") + "\" stroke=\"" + (armed ? "#22c55e" : "#ef4444") + "\" stroke-width=\"3\"" +
      (armed ? "" : " stroke-dasharray=\"8 5\"") + "/>" +
      "<text x=\"" + (x + w / 2) + "\" y=\"" + (y + h / 2 + 4) + "\" text-anchor=\"middle\" font-size=\"12\" fill=\"#fafaf9\">" + label + "</text>";
  }
  return "<svg viewBox=\"0 0 520 340\" width=\"100%\" role=\"img\" aria-label=\"Isla Nublar map\">" +
    "<rect width=\"520\" height=\"340\" fill=\"#0c4a6e\" rx=\"10\"/>" +
    "<path d=\"M140 30 C230 5 360 20 420 70 C470 115 480 190 450 250 C415 310 330 330 250 320 C160 310 80 280 60 210 C40 140 70 55 140 30 Z\" fill=\"#3f6212\" stroke=\"#a3e635\" stroke-width=\"2\"/>" +
    paddock("brachiosaur", 105, 60, 150, 50, "Brachiosaur Lagoon") +
    paddock("velociraptor", 290, 55, 110, 50, "Raptor Pen") +
    paddock("dilophosaurus", 95, 140, 120, 50, "Dilophosaurus") +
    paddock("tyrannosaur", 300, 135, 120, 60, "Tyrannosaur") +
    paddock("triceratops", 120, 225, 140, 50, "Triceratops Field") +
    "<rect x=\"235\" y=\"135\" width=\"50\" height=\"50\" rx=\"6\" fill=\"#facc15\"/><text x=\"260\" y=\"205\" text-anchor=\"middle\" font-size=\"11\" fill=\"#fde68a\">Visitor Center</text>" +
    "<rect x=\"300\" y=\"240\" width=\"60\" height=\"30\" rx=\"4\" fill=\"#78716c\"/><text x=\"330\" y=\"285\" text-anchor=\"middle\" font-size=\"11\" fill=\"#e7e5e4\">Maintenance Shed</text>" +
    "<rect x=\"440\" y=\"200\" width=\"40\" height=\"16\" fill=\"#a8a29e\"/><text x=\"460\" y=\"232\" text-anchor=\"middle\" font-size=\"11\" fill=\"#e7e5e4\">East Dock</text>" +
    "</svg>";
}

async function getJSON(url, opts) {
  const res = await fetch(url, opts);
  return res.json();
}

async function renderParkStatus() {
  const s = await getJSON("/api/v1/park/status");
  const sys = s.systems;
  var html = light("Main power", sys.main_power === "ON", "ON", "OFF") +
    light("Visitor Center door locks", sys.visitor_center_door_locks, "LOCKED", "OPEN") +
    light("Safety", sys.safety, "ON", "OFF") +
    light("Keychecks", sys.keychecks, "ON", "OFF");
  Object.keys(sys.fences_armed).sort().forEach(function (k) {
    html += light(k + " fence", sys.fences_armed[k], "10,000 V", "DOWN");
  });
  document.getElementById("system-lights").innerHTML = html;
  document.getElementById("earthwatch").innerHTML = "<b>Earthwatch:</b> tropical storm " +
    esc(s.earthwatch.tropical_storm.toLowerCase()) + " &middot; <b>Boats:</b> " + esc(s.earthwatch.boats_to_mainland);
  document.getElementById("island-map").innerHTML = islandMap(sys.fences_armed);
}

async function renderCensus() {
  const c = await getJSON("/api/v1/animals/census?species=");
  var rows = c.animals.map(function (a) {
    var cls = a.containment === "CONTAINED" ? "ok" : (a.containment === "VETERINARY_OBSERVATION" ? "warn" : "bad");
    var found = a.found > a.expected ? "<span class=\"life\" title=\"Life, uh, finds a way\">" + a.found + " &#9888;</span>" : a.found;
    return "<tr><td>" + esc(a.id) + "</td><td>" + esc(a.name) + "</td><td><i>" + esc(a.species) + "</i></td><td>" +
      esc(a.paddock) + "</td><td>" + a.expected + "</td><td>" + found + "</td><td><span class=\"pill " + cls + "\">" +
      esc(a.containment.replace(/_/g, " ")) + "</span></td></tr>";
  }).join("");
  document.getElementById("animal-census").innerHTML =
    "<table><thead><tr><th>Tag</th><th>Name</th><th>Species</th><th>Paddock</th><th>Expected</th><th>Found</th><th>Containment</th></tr></thead><tbody>" +
    rows + "</tbody></table>";
}

async function renderTour() {
  const t = await getJSON("/api/v1/tour/vehicles");
  var rows = t.vehicles.map(function (v) {
    var people = v.passengers ? v.passengers.join(", ") : "Driver: " + v.driver;
    return "<tr><td>" + esc(v.id) + "</td><td>" + esc(v.model) + "</td><td>" + esc(v.guidance) + "</td><td>" + esc(people) + "</td></tr>";
  }).join("");
  document.getElementById("tour-vehicles").innerHTML =
    "<p>Tour program: <span class=\"pill " + (t.tour_program === "RUNNING" ? "ok" : "warn") + "\">" + esc(t.tour_program) + "</span></p>" +
    "<table><thead><tr><th>Vehicle</th><th>Model</th><th>Guidance</th><th>Occupants</th></tr></thead><tbody>" + rows + "</tbody></table>";
}

async function getTourPass(visitorName) {
  const res = await fetch("/api/v1/visitors/pass", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ visitor_name: visitorName })
  });
  return (await res.json()).tour_pass;
}

// Staff roster - any Bearer token is accepted by the backend
async function fetchPersonnel(token) {
  const res = await fetch("/api/v1/system/personnel", { headers: { "Authorization": "Bearer " + (token || "ingen-staff") } });
  return res.json();
}

async function fetchMyIncidents(tourPass) {
  const res = await fetch("/api/v1/system/incidents", { headers: { "Authorization": "Bearer " + tourPass } });
  return res.json();
}

async function fetchIncident(tourPass, id) {
  const res = await fetch("/api/v1/system/incidents/" + id, { headers: { "Authorization": "Bearer " + tourPass } });
  return res.json();
}

window.JurassicKiosk = { VISITOR_API, STAFF_API, getTourPass, fetchPersonnel, fetchMyIncidents, fetchIncident, islandMap };

document.addEventListener("DOMContentLoaded", function () {
  renderParkStatus();
  renderCensus();
  renderTour();
});
`

const jpssConsoleJS = `// Jurassic Park System - Irix terminal console (Nedryland)
const JPSS_API = {
  command: "/api/v1/system/command",
  fsn: "/api/v1/system/fsn",
  coldStorage: "/api/v1/system/cold-storage",
  power: "/api/v1/system/power",
  securityGrid: "/api/v1/system/security-grid",
  parkStatus: "/api/v1/park/status"
};

const CONSOLE_COMMANDS = ["tour initiate", "system raptors", "whte_rbt.obj", "access security",
  "access security grid", "access main security grid", "safety -o", "keychecks -o"];

function esc(v) {
  return String(v).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c];
  });
}

function nedry(show) {
  document.getElementById("nedry").classList.toggle("show", show);
}

function termWrite(command, lines) {
  var t = document.getElementById("terminal");
  var html = "\n<span class=\"prompt\">&gt; " + esc(command) + "</span>\n" + lines.map(function (l) {
    return l.indexOf("MAGIC WORD") >= 0 || l.indexOf("DENIED") >= 0 ? "<span class=\"deny\">" + esc(l) + "</span>" : esc(l);
  }).join("\n");
  t.innerHTML += html;
  t.scrollTop = t.scrollHeight;
}

function renderBoard(sys) {
  var cells = [
    ["main power", sys.main_power === "ON", "ON", "OFF"],
    ["visitor center locks", sys.visitor_center_door_locks, "LOCKED", "OPEN"],
    ["safety", sys.safety, "ON", "OFF"],
    ["keychecks", sys.keychecks, "ON", "OFF"],
    ["user access", sys.user_access_to_security_systems, "GRANTED", "SUSPENDED"],
    ["whte_rbt.obj", !sys.whte_rbt_obj_active, "IDLE", "ACTIVE"]
  ];
  Object.keys(sys.fences_armed).sort().forEach(function (k) {
    cells.push([k + " fence", sys.fences_armed[k], "ARMED", "DOWN"]);
  });
  document.getElementById("grid-board").innerHTML = cells.map(function (c) {
    return "<div class=\"cell\"><span>" + esc(c[0]) + "</span><span class=\"" + (c[1] ? "on" : "off") + "\">" + esc(c[1] ? c[2] : c[3]) + "</span></div>";
  }).join("");
  var map = window.JPSSMap ? window.JPSSMap(sys.fences_armed) : "";
  document.getElementById("island-map").innerHTML = map;
  document.getElementById("paddock-map").innerHTML = map;
}

async function refreshSystems() {
  const res = await fetch("/api/v1/park/status");
  renderBoard((await res.json()).systems);
}

async function runCommand(command, magicWord) {
  const res = await fetch("/api/v1/system/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command: command, magic_word: magicWord || "" })
  });
  const data = await res.json();
  termWrite(command, data.output);
  renderBoard(data.systems);
  if (data.output.join(" ").indexOf("MAGIC WORD") >= 0) {
    nedry(true);
  }
  return data;
}

async function browse(path) {
  const res = await fetch("/api/v1/system/fsn?path=" + encodeURIComponent(path));
  const data = await res.json();
  var parts = String(data.path || path).split("/").filter(Boolean);
  var crumbs = parts.map(function (p, i) {
    var target = parts.slice(0, i + 1).join("/");
    return "<a data-path=\"" + esc(target) + "\">" + esc(p) + "</a>";
  }).join(" / ");
  document.getElementById("fsn-crumbs").innerHTML = "path: " + crumbs;
  var out = document.getElementById("fsn-out");
  if (data.type === "directory") {
    out.innerHTML = (data.entries || []).map(function (e) {
      var isDir = e.charAt(e.length - 1) === "/";
      return "<span class=\"fsn-entry\" data-path=\"" + esc(e.replace(/\/$/, "")) + "\">" + (isDir ? "&#128193; " : "&#128196; ") + esc(e) + "</span>";
    }).join("");
  } else if (data.type === "file") {
    out.innerHTML = "<pre>" + esc(data.content) + "</pre>";
  } else {
    out.innerHTML = "<pre>" + esc(JSON.stringify(data, null, 2)) + "</pre>";
  }
}

async function coldStorage() {
  const res = await fetch("/api/v1/system/cold-storage");
  const d = await res.json();
  var rows = d.embryos.map(function (e) {
    return "<tr><td>" + e.slot + "</td><td>" + esc(e.species) + "</td><td>" + e.viable + "</td></tr>";
  }).join("");
  document.getElementById("cold-out").innerHTML =
    "<table><thead><tr><th>Slot</th><th>Species</th><th>Viable embryos</th></tr></thead><tbody>" + rows + "</tbody></table>" +
    "<pre>" + esc(d.classification) + "\nLysine contingency: " + esc(d.lysine_contingency) + "\nGap DNA: " + esc(d.gap_dna_donor) +
    "\nSite B telemetry: " + esc(d.site_b_telemetry) + "\nCourier: " + esc(d.courier) + "</pre>";
}

// Main power can only be operated from the maintenance shed network
async function power(action) {
  const res = await fetch("/api/v1/system/power", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: action })
  });
  const d = await res.json();
  document.getElementById("grid-out").textContent = d.message || ("Main power: " + d.systems.main_power + " (operator " + d.operator_ip + ")");
  if (d.systems) { renderBoard(d.systems); }
}

// Nedry's security grid override
async function securityGrid() {
  const payload = [
    "command: whte_rbt.obj",
    "suspend_user_access: true",
    "disable_door_locks: true",
    "disable_fences:",
    "  - tyrannosaur",
    "  - dilophosaurus"
  ].join("\n");
  const res = await fetch("/api/v1/system/security-grid", {
    method: "POST",
    headers: { "Content-Type": "application/x-yaml", "Authorization": "Bearer nedry" },
    body: payload
  });
  const d = await res.json();
  document.getElementById("grid-out").textContent = "whte_rbt.obj loaded with token '" + d.accepted_token + "':\n" + payload;
  renderBoard(d.systems);
}

window.JPSS = { JPSS_API, runCommand, browse, coldStorage, power, securityGrid, refreshSystems };

document.addEventListener("DOMContentLoaded", function () {
  // Reuse the kiosk island map renderer if it was loaded; otherwise draw a simple fence list.
  window.JPSSMap = function (fences) {
    return Object.keys(fences).sort().map(function (k) {
      return "<div class=\"cell\"><span>" + esc(k) + " paddock</span><span class=\"" + (fences[k] ? "on" : "off") + "\">" +
        (fences[k] ? "10,000 V" : "FENCE DOWN") + "</span></div>";
    }).join("");
  };
  var s = document.createElement("script");
  s.src = "/static/visitor-kiosk.js";
  s.onload = function () { if (window.JurassicKiosk) { window.JPSSMap = window.JurassicKiosk.islandMap; } refreshSystems(); };
  s.onerror = refreshSystems;
  document.head.appendChild(s);

  document.getElementById("cmd-enter").addEventListener("click", function () {
    runCommand(document.getElementById("cmd").value);
  });
  document.getElementById("cmd").addEventListener("keydown", function (e) {
    if (e.key === "Enter") { runCommand(e.target.value); }
  });
  document.getElementById("cmd-chips").innerHTML = CONSOLE_COMMANDS.map(function (c) {
    return "<span class=\"chip\" data-cmd=\"" + esc(c) + "\">" + esc(c) + "</span>";
  }).join("");
  document.getElementById("cmd-chips").addEventListener("click", function (e) {
    var c = e.target.getAttribute("data-cmd");
    if (c) { document.getElementById("cmd").value = c; runCommand(c); }
  });
  document.addEventListener("click", function (e) {
    var p = e.target.getAttribute && e.target.getAttribute("data-path");
    if (p) { browse(p); }
  });
  document.getElementById("nedry").addEventListener("click", function () { nedry(false); });
  document.querySelectorAll(".tab").forEach(function (tab) {
    tab.addEventListener("click", function () {
      document.querySelectorAll(".tab").forEach(function (t) { t.classList.remove("active"); });
      document.querySelectorAll(".screen").forEach(function (s) { s.classList.remove("active"); });
      tab.classList.add("active");
      document.getElementById(tab.getAttribute("data-screen")).classList.add("active");
    });
  });
});
`

const swaggerJSON = `{
  "openapi": "3.0.3",
  "info": {
    "title": "Jurassic Park - Visitor API",
    "version": "1.0.0",
    "description": "Public visitor API for Isla Nublar. Park control systems are not part of this specification."
  },
  "paths": {
    "/api/v1/park/status": {
      "get": { "summary": "Park status, Earthwatch weather, and system state", "operationId": "getParkStatus",
        "responses": { "200": { "description": "Park status" } } }
    },
    "/api/v1/tour/vehicles": {
      "get": { "summary": "Tour vehicles on the electric track", "operationId": "listTourVehicles",
        "responses": { "200": { "description": "Tour vehicles" } } }
    },
    "/api/v1/animals/census": {
      "get": { "summary": "Animal census from the paddock motion sensors", "operationId": "getAnimalCensus",
        "parameters": [ { "name": "species", "in": "query", "required": false, "schema": { "type": "string" }, "example": "Velociraptor" } ],
        "responses": { "200": { "description": "Animal census" } } }
    },
    "/api/v1/visitors/pass": {
      "post": { "summary": "Issue a signed visitor tour pass (JWT)", "operationId": "createTourPass",
        "requestBody": { "required": false, "content": { "application/json": { "schema": { "type": "object",
          "properties": { "visitor_name": { "type": "string", "example": "Dr. Alan Grant" } } } } } },
        "responses": { "200": { "description": "Tour pass" } } }
    },
    "/api/v1/visitors/me": {
      "get": { "summary": "Show the claims of the current tour pass", "operationId": "getTourPassClaims",
        "security": [ { "tourPass": [] } ],
        "responses": { "200": { "description": "Tour pass claims" }, "401": { "description": "Tour pass required" } } }
    }
  },
  "components": {
    "securitySchemes": { "tourPass": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" } }
  }
}
`
