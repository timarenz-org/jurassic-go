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
    body { font-family: system-ui, sans-serif; background: #1c1917; color: #fafaf9; margin: 0; padding: 2rem; }
    header { border-bottom: 3px solid #dc2626; padding-bottom: 1rem; margin-bottom: 1.5rem; }
    h1 { color: #facc15; margin: 0; }
    .card { background: #292524; border: 1px solid #44403c; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
    pre { background: #0c0a09; color: #a3e635; padding: 1rem; border-radius: 6px; overflow-x: auto; }
    a { color: #38bdf8; }
    footer { margin-top: 2rem; font-size: 0.8rem; color: #78716c; }
  </style>
</head>
<body>
  <header>
    <h1>Welcome to Jurassic Park</h1>
    <p>Isla Nublar, Costa Rica &mdash; "Spared no expense." &mdash; <a href="/swagger.json">Visitor API</a></p>
  </header>
  <div class="card"><h2>Park Status &amp; Earthwatch</h2><pre id="park-status">Loading...</pre></div>
  <div class="card"><h2>Tour Vehicles</h2><pre id="tour-vehicles">Loading...</pre></div>
  <div class="card"><h2>Animal Paddocks</h2><pre id="animal-census">Loading...</pre></div>
  <footer>InGen staff: <a href="/control-room">Control Room</a></footer>
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
    body { font-family: monospace; background: #000; color: #4ade80; padding: 2rem; }
    h1 { color: #ef4444; }
    .panel { border: 1px solid #22c55e; padding: 1rem; margin-bottom: 1rem; }
    input { background: #000; color: #4ade80; border: 1px solid #22c55e; width: 60%; font-family: monospace; }
    button { background: #052e16; color: #4ade80; border: 1px solid #22c55e; font-family: monospace; }
    a { color: #facc15; }
  </style>
</head>
<body>
  <h1>Jurassic Park, System Security Interface &mdash; Version 4.0.5, Alpha</h1>
  <p>Irix Terminal &middot; Central Park Control Console &middot; <a href="/">Visitor Center</a></p>
  <div class="panel">
    <h3>Central Park Control Console</h3>
    <input id="cmd" placeholder="access main security grid" />
    <button onclick="JPSS.runCommand(document.getElementById('cmd').value)">Enter</button>
    <pre id="terminal">Ready...</pre>
  </div>
  <div class="panel">
    <h3>FSN &mdash; File System Navigator</h3>
    <button onclick="JPSS.browse('fsn')">Browse</button>
    <pre id="fsn-out"></pre>
  </div>
  <div class="panel">
    <h3>Hatchery &mdash; Embryo Cold Storage</h3>
    <button onclick="JPSS.coldStorage()">Inventory</button>
    <pre id="cold-out"></pre>
  </div>
  <div class="panel">
    <h3>Main Power &amp; Security Grid</h3>
    <button onclick="JPSS.power('reboot')">Reboot main power</button>
    <button onclick="JPSS.securityGrid()">Load whte_rbt.obj</button>
    <pre id="grid-out"></pre>
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

async function show(id, url) {
  const res = await fetch(url);
  document.getElementById(id).textContent = JSON.stringify(await res.json(), null, 2);
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

window.JurassicKiosk = { VISITOR_API, STAFF_API, getTourPass, fetchPersonnel, fetchMyIncidents, fetchIncident };

document.addEventListener("DOMContentLoaded", function () {
  show("park-status", "/api/v1/park/status");
  show("tour-vehicles", "/api/v1/tour/vehicles");
  show("animal-census", "/api/v1/animals/census?species=");
});
`

const jpssConsoleJS = `// Jurassic Park System - Irix terminal console (Nedryland)
const JPSS_API = {
  command: "/api/v1/system/command",
  fsn: "/api/v1/system/fsn",
  coldStorage: "/api/v1/system/cold-storage",
  power: "/api/v1/system/power",
  securityGrid: "/api/v1/system/security-grid"
};

function print(id, data) {
  document.getElementById(id).textContent = typeof data === "string" ? data : JSON.stringify(data, null, 2);
}

async function runCommand(command, magicWord) {
  const res = await fetch("/api/v1/system/command", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ command: command, magic_word: magicWord || "" })
  });
  const data = await res.json();
  print("terminal", data.output.join("\n"));
  return data;
}

async function browse(path) {
  const res = await fetch("/api/v1/system/fsn?path=" + encodeURIComponent(path));
  print("fsn-out", await res.json());
}

async function coldStorage() {
  const res = await fetch("/api/v1/system/cold-storage");
  print("cold-out", await res.json());
}

// Main power can only be operated from the maintenance shed network
async function power(action) {
  const res = await fetch("/api/v1/system/power", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: action })
  });
  print("grid-out", await res.json());
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
  print("grid-out", await res.json());
}

window.JPSS = { JPSS_API, runCommand, browse, coldStorage, power, securityGrid };
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
