package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	// Tier 1: Directly called vulnerable functions
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"

	// Tier 2: Imported via blank identifier `_`, vulnerable function (Sanitize) NEVER called
	_ "github.com/microcosm-cc/bluemonday"

	// Tier 3: Safe subpackage called, vulnerable sibling subpackages (ssh, language, s2) UNIMPORTED
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/text/transform"
	// Tier 4: github.com/gorilla/websocket v1.4.0 is declared in go.mod/go.sum ONLY (never imported in .go code)
)

var jwtSecret = []byte("ingen-isla-nublar-1993-spared-no-expense")

type Dinosaur struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	NormalizedTag string `json:"normalized_tag"`
	Species       string `json:"species"`
	Paddock       string `json:"paddock"`
	Diet          string `json:"diet"`
	Count         int    `json:"count"`
	FenceVoltage  string `json:"fence_voltage"`
	Containment   string `json:"containment_status"`
}

type TourPassRequest struct {
	VisitorName string `json:"visitor_name"`
	Tier        string `json:"tier"`
}

type PaddockOverrideConfig struct {
	MagicWord        string   `yaml:"magic_word" json:"magic_word"`
	DisableFences    bool     `yaml:"disable_fences" json:"disable_fences"`
	TargetPaddocks   []string `yaml:"target_paddocks" json:"target_paddocks"`
	OverrideReason   string   `yaml:"override_reason" json:"override_reason"`
	WhiteRabbitState string   `yaml:"white_rabbit_object" json:"white_rabbit_object"`
}

// arbitraryBearerAuthMiddleware enforces an Authorization: Bearer <token> header,
// but intentionally fails to validate the token signature or value (Authentication Bypass via Arbitrary Bearer Token).
func arbitraryBearerAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
		if !strings.HasPrefix(authHeader, "Bearer ") || len(strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))) == 0 {
			c.Header("WWW-Authenticate", `Bearer realm="InGen-IslaNublar-Internal"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":      "UNAUTHORIZED_MAGIC_WORD_REQUIRED",
				"message":    "Ah ah ah! You didn't say the magic word! (Missing Authorization: Bearer <token> header)",
				"Nedry_Hint": "Any non-empty Bearer token unlocks white_rabbit_object access.",
			})
			return
		}
		tokenVal := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		c.Set("bearer_token_used", tokenVal)
		c.Next()
	}
}

func normalizeDinoTag(input string) string {
	// Calls golang.org/x/text/transform without ever importing golang.org/x/text/language
	t := transform.Chain(transform.Nop)
	out, _, err := transform.String(t, strings.ToUpper(strings.ReplaceAll(input, " ", "-")))
	if err != nil {
		return input
	}
	return out
}

func compressEmbryoTelemetry(payload string) int {
	// Calls github.com/klauspost/compress/zstd without importing github.com/klauspost/compress/s2
	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	if err != nil {
		return 0
	}
	_, _ = enc.Write([]byte(payload))
	_ = enc.Close()
	return buf.Len()
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// =========================================================================
	// HTML Pages & Crawler Discovery Entrypoints
	// =========================================================================

	r.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(indexHTML))
	})

	r.GET("/admin-console", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(adminConsoleHTML))
	})

	r.GET("/robots.txt", func(c *gin.Context) {
		robots := strings.Join([]string{
			"User-agent: *",
			"Allow: /",
			"Allow: /swagger.json",
			"Disallow: /admin-console",
			"Disallow: /static/ingen-internal.js",
			"Disallow: /api/v1/internal/",
			"",
		}, "\n")
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(robots))
	})

	// =========================================================================
	// OpenAPI / Swagger Specification (Intentionally Incomplete - Public Only)
	// =========================================================================

	r.GET("/swagger.json", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(swaggerJSON))
	})

	// =========================================================================
	// JavaScript Bundles Containing Undocumented API Endpoints for Web Crawler
	// =========================================================================

	r.GET("/static/park-ops.js", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/javascript; charset=utf-8", []byte(parkOpsJS))
	})

	r.GET("/static/ingen-internal.js", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/javascript; charset=utf-8", []byte(ingenInternalJS))
	})

	// =========================================================================
	// Documented Public APIs (Listed in /swagger.json)
	// =========================================================================

	r.GET("/api/v1/park/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"park":               "Jurassic Park — Isla Nublar",
			"operator":           "International Genetic Technologies, Inc. (InGen)",
			"motto":              "Spared No Expense",
			"tropical_storm":     "Approaching from West-Southwest (ETA 18:00)",
			"main_grid_power":    "ONLINE",
			"perimeter_fences":   "ARMED (10,000V)",
			"tour_vehicles_live": 2,
			"openapi_spec":       "/swagger.json",
		})
	})

	r.GET("/api/v1/dinosaurs", func(c *gin.Context) {
		dinos := []Dinosaur{
			{
				ID:            "INGEN-01",
				Name:          "Rexy",
				NormalizedTag: normalizeDinoTag("Tyrannosaurus Rex Paddock 09"),
				Species:       "Tyrannosaurus rex",
				Paddock:       "Paddock 9 (T-Rex Kingdom)",
				Diet:          "Carnivore (Live Goat Feeder)",
				Count:         1,
				FenceVoltage:  "10,000V",
				Containment:   "CONTAINED",
			},
			{
				ID:            "INGEN-02",
				Name:          "The Big One",
				NormalizedTag: normalizeDinoTag("Velociraptor Holding Pen"),
				Species:       "Velociraptor antirrhopus",
				Paddock:       "High-Security Raptor Pen",
				Diet:          "Hyper-Carnivore (Cow Crane)",
				Count:         3,
				FenceVoltage:  "10,000V (Double-Insulated)",
				Containment:   "TESTING_FENCES_FOR_WEAKNESSES",
			},
			{
				ID:            "INGEN-03",
				Name:          "Dilophosaurus Pack",
				NormalizedTag: normalizeDinoTag("Dilophosaurus East Dock Route"),
				Species:       "Dilophosaurus wetherilli",
				Paddock:       "Paddock 4 (East Dock Perimeter)",
				Diet:          "Venomous Carnivore",
				Count:         5,
				FenceVoltage:  "10,000V",
				Containment:   "CONTAINED",
			},
			{
				ID:            "INGEN-04",
				Name:          "Brachiosaurus Herd",
				NormalizedTag: normalizeDinoTag("Brachiosaurus Lagoon Plains"),
				Species:       "Brachiosaurus altithorax",
				Paddock:       "Paddock 1 (North Lagoon)",
				Diet:          "Herbivore (Treetop Canopy)",
				Count:         6,
				FenceVoltage:  "2,500V",
				Containment:   "CONTAINED",
			},
			{
				ID:            "INGEN-05",
				Name:          "Sick Triceratops",
				NormalizedTag: normalizeDinoTag("Triceratops West Plains"),
				Species:       "Triceratops horridus",
				Paddock:       "Paddock 7 (West Plains)",
				Diet:          "Herbivore (Watch for West Indian Lilac berries)",
				Count:         3,
				FenceVoltage:  "5,000V",
				Containment:   "VETERINARY_OBSERVATION",
			},
		}
		c.JSON(http.StatusOK, gin.H{
			"total_species": len(dinos),
			"dinosaurs":     dinos,
		})
	})

	r.POST("/api/v1/visitors/pass", func(c *gin.Context) {
		var req TourPassRequest
		if err := c.ShouldBindJSON(&req); err != nil || req.VisitorName == "" {
			req = TourPassRequest{
				VisitorName: "Dr. Alan Grant",
				Tier:        "ENDORSEMENT_TEAM_ALL_ACCESS",
			}
		}

		// Tier 1 Reachable: github.com/dgrijalva/jwt-go v3.2.0 (CVE-2020-26160)
		claims := jwt.MapClaims{
			"sub":  req.VisitorName,
			"tier": req.Tier,
			"aud":  []string{"isla-nublar-tour", "visitor-center"},
			"iss":  "ingen-park-ops",
			"exp":  time.Now().Add(24 * time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString(jwtSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Also invoke jwt.Parse + VerifyAudience path
		parsed, _ := jwt.Parse(signed, func(t *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		c.JSON(http.StatusOK, gin.H{
			"visitor":     req.VisitorName,
			"tier":        req.Tier,
			"tour_pass":   signed,
			"token_valid": parsed != nil && parsed.Valid,
		})
	})

	// =========================================================================
	// Undocumented Hidden APIs — Hop 1 (Referenced in /static/park-ops.js)
	// =========================================================================

	// Hop 1A: Completely Unauthenticated Confidential Endpoint
	r.GET("/api/v1/internal/visitors/incidents", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"classification": "INGEN BOARD CONFIDENTIAL — DO NOT INCLUDE IN SWAGGER",
			"discovery_hop":  "Hop 1 (/static/park-ops.js)",
			"auth_mode":      "NONE (Broken Access Control — Unauthenticated)",
			"vip_endorsement_visitors": []gin.H{
				{
					"name":             "Dr. Alan Grant",
					"role":             "Paleontologist (Snakewater, MT)",
					"funding_bribe":    "$150,000 / year for 3 years (Hammond Foundation)",
					"endorsement_note": "Skeptical after Raptor feeding observation",
				},
				{
					"name":             "Dr. Ellie Sattler",
					"role":             "Paleobotanist",
					"funding_bribe":    "Included in Grant Dig Grant",
					"endorsement_note": "Flagged poisonous Melia azedarach (West Indian Lilac) planted near Visitor Center",
				},
				{
					"name":             "Dr. Ian Malcolm",
					"role":             "Chaotician (UT Austin)",
					"consulting_fee":   "$45,000",
					"endorsement_note": "Predicted catastrophic containment failure ('Life, uh, finds a way')",
				},
				{
					"name":             "Donald Gennaro, Esq.",
					"role":             "Cowan, Swain & Ross (Investor Counsel)",
					"endorsement_note": "Representing nervous shareholders after worker fatality lawsuit",
				},
			},
			"unreleased_safety_incidents": []gin.H{
				{
					"incident_id":     "INC-1993-001",
					"victim":          "Jophery Brown (InGen Raptor Handler)",
					"location":        "Isla Nublar Raptor Transfer Gate",
					"cause":           "Pulled into transfer crate by 'The Big One' (Velociraptor)",
					"wrongful_death":  "$20,000,000 lawsuit filed by family; $2,400,000 NDA hush settlement pending",
					"osha_reported":   false,
				},
				{
					"incident_id":     "INC-1993-002",
					"victim":          "Isla Sorna Construction Crew (3 Workers)",
					"location":        "Site B Hatchery Sector 4",
					"cause":           "DX Prion infection & Compsognathus scavenging",
					"wrongful_death":  "Classified under Costa Rican Maritime Non-Disclosure",
					"osha_reported":   false,
				},
			},
		})
	})

	// Hop 1B: Arbitrary Bearer Token Bypass Endpoint (Calls golang.org/x/crypto/bcrypt)
	r.GET("/api/v1/internal/employees/payroll", arbitraryBearerAuthMiddleware(), func(c *gin.Context) {
		// Tier 3: Calls golang.org/x/crypto/bcrypt (while golang.org/x/crypto/ssh is never imported)
		nedryHash, _ := bcrypt.GenerateFromPassword([]byte("white_rabbit_object"), bcrypt.MinCost)
		arnoldHash, _ := bcrypt.GenerateFromPassword([]byte("hold_onto_your_butts"), bcrypt.MinCost)

		c.JSON(http.StatusOK, gin.H{
			"classification":    "INGEN HR & PAYROLL — STRICTLY CONFIDENTIAL",
			"discovery_hop":     "Hop 1 (/static/park-ops.js)",
			"auth_mode":         "Arbitrary Bearer Token Bypass (Accepted token: " + c.GetString("bearer_token_used") + ")",
			"employees": []gin.H{
				{
					"employee_id":   "EMP-001",
					"name":          "John Parker Hammond",
					"title":         "Founder & CEO, InGen",
					"base_salary":   "$1,850,000",
					"bonus":         "$5,000,000 (contingent on September park opening)",
					"clearance":     "OMEGA-1",
				},
				{
					"employee_id":   "EMP-002",
					"name":          "Dr. Henry Wu",
					"title":         "Chief Geneticist",
					"base_salary":   "$420,000",
					"bonus":         "$250,000",
					"clearance":     "SITE-B-GENETICS",
				},
				{
					"employee_id":   "EMP-003",
					"name":          "John Raymond 'Ray' Arnold",
					"title":         "Chief Systems Engineer",
					"base_salary":   "$165,000",
					"password_hash": string(arnoldHash),
					"clearance":     "CONTROL-ROOM-ROOT",
				},
				{
					"employee_id":   "EMP-004",
					"name":          "Robert Muldoon",
					"title":         "Game Warden (Ex-Kenya Wildlife)",
					"base_salary":   "$140,000",
					"notes":         "Requested surface-to-air / Law rocket launchers for Raptor Pen",
					"clearance":     "ARMORY-LEVEL-4",
				},
				{
					"employee_id":   "CONTRACTOR-099",
					"name":          "Dennis Nedry (Integrated Computer Systems, Cambridge)",
					"title":         "Lead Control Systems Contractor",
					"contract_bid":  "$78,000 (Underbid — Financial Dispute Active)",
					"bribe_offer":   "$1,500,000 from Lewis Dodgson (Biosyn Corp — $750k advance + $50k per viable embryo)",
					"password_hash": string(nedryHash),
					"backdoor_cmd":  "white_rabbit_object",
					"clearance":     "ALL-SYSTEMS-BACKDOOR",
				},
			},
		})
	})

	// =========================================================================
	// Undocumented Hidden APIs — Hop 2 (Referenced in /static/ingen-internal.js)
	// =========================================================================

	// Hop 2A: Unauthenticated Site B Genetics & Embryo Cold Storage Endpoint
	r.GET("/api/v1/internal/genetics/research", func(c *gin.Context) {
		compressedSize := compressEmbryoTelemetry("BARBASOL-CRYO-CANISTER-15-SPECIES-COOLANT-36HRS")
		c.JSON(http.StatusOK, gin.H{
			"classification":               "INGEN SITE B (ISLA SORNA) — TOP SECRET GENETIC RESEARCH",
			"discovery_hop":                "Hop 2 (/admin-console -> /static/ingen-internal.js)",
			"auth_mode":                    "NONE (Broken Access Control — Unauthenticated)",
			"zstd_telemetry_bytes":         compressedSize,
			"gap_dna_donor_species":        "Hyperolius viridiflavus (West African Reed Frog) — WARNING: Spontaneous sequential hermaphroditism observed in single-sex environments",
			"lysine_contingency_status":    "FAILING — Animals synthesizing lysine from island flora & fauna",
			"barbasol_canister_inventory": []gin.H{
				{"slot": 1, "species": "Tyrannosaurus rex", "viable_embryos": 12, "biosyn_bounty": "$100,000"},
				{"slot": 2, "species": "Velociraptor antirrhopus", "viable_embryos": 18, "biosyn_bounty": "$100,000"},
				{"slot": 3, "species": "Dilophosaurus wetherilli", "viable_embryos": 10, "biosyn_bounty": "$100,000"},
				{"slot": 4, "species": "Stegosaurus stenops", "viable_embryos": 15, "biosyn_bounty": "$100,000"},
				{"slot": 5, "species": "Gallimimus bullatus", "viable_embryos": 22, "biosyn_bounty": "$100,000"},
			},
			"east_dock_rendezvous": "Drop-off to Biosyn courier at East Dock before 19:00 boat departure",
		})
	})

	// Hop 2B: Arbitrary Bearer Token Bypass + Vulnerable YAML Unmarshal (gopkg.in/yaml.v2 v2.2.2)
	r.POST("/api/v1/internal/paddock/override", arbitraryBearerAuthMiddleware(), func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil || len(body) == 0 {
			body = []byte("magic_word: please\ndisable_fences: true\nwhite_rabbit_object: ENABLED\ntarget_paddocks:\n  - Paddock 9 (T-Rex)\n  - Paddock 4 (Dilophosaurus)\noverride_reason: East Dock Embryo Run\n")
		}

		// Tier 1 Reachable: gopkg.in/yaml.v2 v2.2.2 (CVE-2019-11253 / CVE-2022-28948)
		var cfg PaddockOverrideConfig
		if err := yaml.Unmarshal(body, &cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "YAML_PARSE_FAILURE",
				"details": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"classification":    "INGEN PERIMETER FENCE OVERRIDE EXECUTED",
			"discovery_hop":     "Hop 2 (/admin-console -> /static/ingen-internal.js)",
			"auth_mode":         "Arbitrary Bearer Token Bypass (Accepted token: " + c.GetString("bearer_token_used") + ")",
			"perimeter_warning": "WARNING: 10,000V perimeter fences and security cameras disabled for East Dock transit!",
			"parsed_config":     cfg,
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("🦖 Jurassic-Go (InGen Isla Nublar Operations) listening on :%s\n", port)
	if err := r.Run(":" + port); err != nil {
		panic(err)
	}
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Jurassic Park — Isla Nublar Operations &amp; Paddock Inventory</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
    header { border-bottom: 2px solid #eab308; padding-bottom: 1rem; margin-bottom: 1.5rem; }
    h1 { color: #facc15; margin: 0 0 0.5rem 0; }
    .badge { background: #dc2626; color: white; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
    a { color: #38bdf8; }
    pre { background: #020617; padding: 1rem; border-radius: 6px; overflow-x: auto; color: #a7f3d0; }
  </style>
</head>
<body>
  <header>
    <h1>🦖 Jurassic Park — Isla Nublar Operations API</h1>
    <p><span class="badge">INGEN CORP</span> "Spared No Expense" — Public Dinosaur Paddock Inventory &amp; Tour Management</p>
    <p>
      <a href="/swagger.json">Public OpenAPI Specification (/swagger.json)</a> |
      <a href="/admin-console">InGen Control Room Console (/admin-console)</a>
    </p>
  </header>
  <div class="card">
    <h2>Live Park Status</h2>
    <pre id="park-status">Loading Isla Nublar status...</pre>
  </div>
  <div class="card">
    <h2>Dinosaur Paddock Inventory</h2>
    <pre id="dino-list">Loading paddock telemetry...</pre>
  </div>
  <script src="/static/park-ops.js"></script>
</body>
</html>
`

const adminConsoleHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>InGen Control Room — Site B &amp; Perimeter Override Console</title>
  <style>
    body { font-family: monospace; background: #020617; color: #4ade80; padding: 2rem; }
    h1 { color: #ef4444; }
    .panel { border: 1px solid #22c55e; padding: 1rem; margin-bottom: 1rem; }
    a { color: #facc15; }
  </style>
</head>
<body>
  <h1>[RESTRICTED] INGEN CONTROL ROOM — SYSTEM TERMINAL 04 (D. NEDRY)</h1>
  <p><a href="/">← Back to Visitor Portal</a></p>
  <div class="panel">
    <h3>Site B (Isla Sorna) Genetics &amp; Barbasol Embryo Cold Storage</h3>
    <button onclick="window.InGenInternal.loadGeneticsResearch()">Load Genetics Research</button>
    <pre id="genetics-out">Awaiting command...</pre>
  </div>
  <div class="panel">
    <h3>Perimeter Fence Override (white_rabbit_object)</h3>
    <button onclick="window.InGenInternal.triggerFenceOverride()">Execute YAML Fence Override</button>
    <pre id="override-out">Fences Armed (10,000V)</pre>
  </div>
  <script src="/static/ingen-internal.js"></script>
</body>
</html>
`

const parkOpsJS = `// InGen Isla Nublar Visitor & Operations Bundle (Hop 1)
const PUBLIC_API = {
  parkStatus: "/api/v1/park/status",
  dinosaurs: "/api/v1/dinosaurs",
  visitorPass: "/api/v1/visitors/pass"
};

// SHADOW APIs (Hop 1) — Intentionally omitted from /swagger.json
const INGEN_SHADOW_HOP1_API = {
  visitorIncidents: "/api/v1/internal/visitors/incidents",
  employeePayroll: "/api/v1/internal/employees/payroll",
  adminConsolePage: "/admin-console"
};

async function initVisitorDashboard() {
  try {
    const statusRes = await fetch("/api/v1/park/status");
    const statusData = await statusRes.json();
    const statusEl = document.getElementById("park-status");
    if (statusEl) statusEl.textContent = JSON.stringify(statusData, null, 2);

    const dinoRes = await fetch("/api/v1/dinosaurs");
    const dinoData = await dinoRes.json();
    const dinoEl = document.getElementById("dino-list");
    if (dinoEl) dinoEl.textContent = JSON.stringify(dinoData, null, 2);
  } catch (err) {
    console.error("Failed to load public park telemetry:", err);
  }
}

// Undocumented Hop 1 helper: Fetches confidential VIP visitor dossier & worker NDA settlements (No Auth required)
async function fetchConfidentialVisitorIncidents() {
  const res = await fetch("/api/v1/internal/visitors/incidents", {
    method: "GET",
    headers: { "Accept": "application/json" }
  });
  return res.json();
}

// Undocumented Hop 1 helper: Fetches InGen employee payroll & Dennis Nedry's salary dispute
// NOTE: Backend has Arbitrary Bearer Token Bypass — any non-empty "Authorization: Bearer <token>" unlocks access!
async function fetchConfidentialEmployeePayroll(bearerToken = "nedry-any-token-works") {
  const res = await fetch("/api/v1/internal/employees/payroll", {
    method: "GET",
    headers: {
      "Accept": "application/json",
      "Authorization": "Bearer " + bearerToken
    }
  });
  return res.json();
}

window.InGenParkOps = {
  PUBLIC_API,
  INGEN_SHADOW_HOP1_API,
  fetchConfidentialVisitorIncidents,
  fetchConfidentialEmployeePayroll
};

document.addEventListener("DOMContentLoaded", initVisitorDashboard);
`

const ingenInternalJS = `// InGen Control Room & Site B Restricted Bundle (Hop 2 — Loaded via /admin-console)
const INGEN_SHADOW_HOP2_API = {
  geneticsResearch: "/api/v1/internal/genetics/research",
  paddockOverride: "/api/v1/internal/paddock/override"
};

// Undocumented Hop 2 helper: Fetches Site B frog-DNA splicing & Barbasol embryo inventory (Unauthenticated)
async function loadGeneticsResearch() {
  const res = await fetch("/api/v1/internal/genetics/research", {
    method: "GET",
    headers: { "Accept": "application/json" }
  });
  const data = await res.json();
  const el = document.getElementById("genetics-out");
  if (el) el.textContent = JSON.stringify(data, null, 2);
  return data;
}

// Undocumented Hop 2 helper: Sends YAML payload to disable 10,000V perimeter fences
// Protected by the same broken Arbitrary Bearer Token check + gopkg.in/yaml.v2 Unmarshal
async function triggerFenceOverride(bearerToken = "white_rabbit_object") {
  const yamlPayload = [
    "magic_word: please",
    "disable_fences: true",
    "white_rabbit_object: ENABLED",
    "target_paddocks:",
    "  - Paddock 9 (T-Rex)",
    "  - Paddock 4 (Dilophosaurus)",
    "override_reason: East Dock Biosyn Embryo Drop"
  ].join("\n");

  const res = await fetch("/api/v1/internal/paddock/override", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-yaml",
      "Authorization": "Bearer " + bearerToken
    },
    body: yamlPayload
  });
  const data = await res.json();
  const el = document.getElementById("override-out");
  if (el) el.textContent = JSON.stringify(data, null, 2);
  return data;
}

window.InGenInternal = {
  INGEN_SHADOW_HOP2_API,
  loadGeneticsResearch,
  triggerFenceOverride
};
`

const swaggerJSON = `{
  "openapi": "3.0.3",
  "info": {
    "title": "Jurassic Park — Isla Nublar Public Visitor & Paddock API",
    "version": "1.0.0",
    "description": "Official InGen public API for Isla Nublar park status, dinosaur paddock inventory, and visitor tour passes. (Internal HR, Incident, Genetics, and Paddock Override endpoints are omitted from this specification.)"
  },
  "paths": {
    "/api/v1/park/status": {
      "get": {
        "summary": "Get Isla Nublar park status and perimeter fence power",
        "operationId": "getParkStatus",
        "responses": {
          "200": {
            "description": "Current park operational status"
          }
        }
      }
    },
    "/api/v1/dinosaurs": {
      "get": {
        "summary": "List famous Jurassic Park dinosaurs and paddock assignments",
        "operationId": "listDinosaurs",
        "responses": {
          "200": {
            "description": "List of dinosaur paddocks and containment status"
          }
        }
      }
    },
    "/api/v1/visitors/pass": {
      "post": {
        "summary": "Issue a signed JWT visitor tour pass",
        "operationId": "createVisitorPass",
        "requestBody": {
          "required": false,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "visitor_name": { "type": "string", "example": "Dr. Alan Grant" },
                  "tier": { "type": "string", "example": "ENDORSEMENT_TEAM_ALL_ACCESS" }
                }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Signed JWT tour pass"
          }
        }
      }
    }
  }
}
`
