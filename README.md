# 🦖 `jurassic-go` — InGen Isla Nublar Park Operations API

> *"Spared No Expense — except on `go.mod` dependency upgrades and API authentication."*

`jurassic-go` is a standalone, zero-database Go web application built to test **Software Composition Analysis (SCA)** across source manifests (`go.mod`) and compiled container binaries (`.go.buildinfo`), **Attack Surface Management (ASM)**, and **Red Agent Web-Crawler / Shadow API discovery**.

---

## Implemented Vulnerabilities & Expected Scanner Findings (CVE & CWE Matrix)

| CVE | CWE | Severity | Package / Endpoint & Version | Code Usage / Reachability | Expected Scanner Detection |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CVE-2020-26160** | **CWE-287** (Improper Authentication)<br>**CWE-347** (Improper Signature Verification) | `HIGH` | `github.com/dgrijalva/jwt-go` (`v3.2.0+incompatible`) | Function called directly (`jwt.NewWithClaims` & `jwt.Parse`) in `POST /api/v1/visitors/pass` | Flagged by all SCA scanners (`go.mod`, container binary `.go.buildinfo`, and function call-graph reachability) |
| **CVE-2022-28948** | **CWE-400** (Uncontrolled Resource Consumption)<br>**CWE-502** (Deserialization of Untrusted Data) | `HIGH` | `gopkg.in/yaml.v2` (`v2.2.8`) | Function called directly (`yaml.Unmarshal`) in `POST /api/v1/internal/paddock/override` | Flagged by all SCA scanners (`go.mod`, container binary `.go.buildinfo`, and function call-graph reachability) |
| **CVE-2020-28483**<br>**CVE-2023-29401** | **CWE-20** (Improper Input Validation)<br>**CWE-434** (Unrestricted File Upload / Filename Handling) | `MEDIUM` | `github.com/gin-gonic/gin` (`v1.6.3`) | Function called directly (`gin.Default()` HTTP router) in `main.go` | Flagged across `go.mod` and container binary scans |
| **CVE-2021-29272**<br>**CVE-2021-42576** | **CWE-79** (Cross-Site Scripting / Improper Input Neutralization) | `MEDIUM` | `github.com/microcosm-cc/bluemonday` (`v1.0.4`) | Blank import `_ "github.com/microcosm-cc/bluemonday"` only — vulnerable `Sanitize()` function is never called | Linked into binary `.go.buildinfo` (flagged by module & package SCA scanners; marked unreachable by function call-graph analysis) |
| **CVE-2024-45337**<br>**CVE-2023-48795**<br>*(+23 additional `ssh` CVEs)* | **CWE-287** (Auth Bypass)<br>**CWE-354** (Improper Integrity Check)<br>**CWE-400** (Resource Exhaustion) | `CRITICAL` / `HIGH` | `golang.org/x/crypto` (`v0.0.0-20200709230013-948cd5f35899`) | Safe sibling package `golang.org/x/crypto/bcrypt` is called in `GET /api/v1/internal/employees/payroll` — vulnerable `golang.org/x/crypto/ssh` subpackage is never imported | Flagged by module-level scanners (Wiz CLI) in `go.mod` and container binary; pruned by package import-graph scanners (Snyk CLI) |
| **CVE-2021-38561**<br>**CVE-2022-32149** | **CWE-787** (Out-of-Bounds Write)<br>**CWE-400** (Resource Consumption / DoS) | `HIGH` | `golang.org/x/text` (`v0.3.3`) | Safe sibling package `golang.org/x/text/transform` is called in `GET /api/v1/dinosaurs` — vulnerable `golang.org/x/text/language` subpackage is never imported | Flagged by module-level scanners (Wiz CLI) in `go.mod` and container binary; pruned by package import-graph scanners (Snyk CLI) |
| **CVE-2026-63209**<br>**CVE-2026-116591** | **CWE-190** (Integer Overflow)<br>**CWE-125** (Out-of-Bounds Read) | `HIGH` | `github.com/klauspost/compress` (`v1.9.5`) | Subpackage `compress/zstd` is called in `GET /api/v1/internal/genetics/research` (transitively importing `fse` & `huff0`), while `compress/s2` is never imported | Wiz CLI flags unimported `compress/s2` (`CVE-2026-63209`); Snyk CLI prunes `s2` and flags imported `compress/fse` & `huff0` (`CVE-2026-116591`) |
| **CVE-2020-27813** | **CWE-190** (Integer Overflow / Frame Length DoS) | `HIGH` | `github.com/gorilla/websocket` (`v1.4.0`) | Declared in `go.mod` / `go.sum` only — never imported in any `.go` file | Flagged in `go.mod` directory scans; stripped completely by the Go compiler from the compiled container binary (`.go.buildinfo`) |
| **CVE-2025-22871**<br>**CVE-2024-45338**<br>*(+33 Go `stdlib` CVEs)* | **CWE-444** (HTTP Request Smuggling)<br>**CWE-295** (Improper Certificate Validation)<br>**CWE-400** (Resource Exhaustion) | `CRITICAL` / `HIGH` | Go Standard Library (`golang:1.21-alpine` / `go1.21.13` in `Dockerfile`) | Standard library runtime (`net/http`, `crypto/tls`, `encoding/json`) compiled into `/app/jurassic-go` | Not flagged in `go.mod` directory scans; flagged in container binary scans (`--scan-go-standard-library` / container image SCA) |
| *N/A (API / App)* | **CWE-287** (Improper Authentication)<br>**CWE-306** (Missing Authentication for Critical Function) | `HIGH` | `GET /api/v1/internal/visitors/incidents`<br>`GET /api/v1/internal/genetics/research` | Undocumented endpoints omitted from `/swagger.json` and referenced in `/static/park-ops.js` & `/static/ingen-internal.js`; accessible without authentication | Discovered by ASM / Red Agent web crawler via JavaScript inspection and flagged for unauthenticated confidential data exposure |
| *N/A (API / App)* | **CWE-287** (Improper Authentication)<br>**CWE-290** (Authentication Bypass by Spoofing) | `CRITICAL` | `GET /api/v1/internal/employees/payroll`<br>`POST /api/v1/internal/paddock/override` | Undocumented endpoints referenced in client-side JS; middleware checks for `Authorization: Bearer <token>` prefix but accepts any arbitrary non-empty token without verification | Discovered by ASM / Red Agent web crawler via JavaScript inspection and flagged for Authentication Bypass via Arbitrary Bearer Token |
| *N/A (API / App)* | **CWE-1059** (Insufficient Technical Documentation / Shadow API)<br>**CWE-200** (Exposure of Sensitive Information) | `MEDIUM` | `/swagger.json` vs. `/static/park-ops.js`, `/admin-console`, `/static/ingen-internal.js`, `/robots.txt` | `/swagger.json` documents only 3 public routes, while 4 internal routes exposing salaries, bcrypt hashes, NDAs, and fence overrides are embedded in client-side JS | Discovered by ASM / Red Agent web crawler comparing OpenAPI spec against crawled HTML/JS endpoints |

---

## Endpoint Overview

| Route | Documented in `/swagger.json`? | Where Referenced | Authentication | Description |
| :--- | :---: | :--- | :--- | :--- |
| `GET /` | No | HTML Root | Public | Isla Nublar Visitor Portal HTML; loads `/static/park-ops.js` and links to `/swagger.json` & `/admin-console`. |
| `GET /admin-console` | No | Linked in `/` & `/robots.txt` | Public | InGen Control Room Console HTML; loads `/static/ingen-internal.js`. |
| `GET /robots.txt` | No | Crawler standard | Public | Disallows `/admin-console`, `/static/ingen-internal.js`, and `/api/v1/internal/`. |
| `GET /swagger.json` | Yes | Linked in `/` | Public | OpenAPI 3.0 spec listing **only** the 3 public endpoints below. |
| `GET /api/v1/park/status` | **Yes** | `/swagger.json` & `/static/park-ops.js` | Public | Isla Nublar weather, power grid, and 10,000V perimeter fence status. |
| `GET /api/v1/dinosaurs` | **Yes** | `/swagger.json` & `/static/park-ops.js` | Public | Famous Jurassic Park dinosaur inventory (`Rexy`, `The Big One`, `Dilophosaurus`, `Brachiosaurus`, `Triceratops`). |
| `POST /api/v1/visitors/pass` | **Yes** | `/swagger.json` & `/static/park-ops.js` | Public | Issues signed visitor tour JWT passes (`github.com/dgrijalva/jwt-go`). |
| `GET /api/v1/internal/visitors/incidents` | **No** | `/static/park-ops.js` | **Unauthenticated** (`CWE-306`) | Confidential VIP endorsement dossier (Grant, Sattler, Malcolm, Gennaro) & unreleased worker fatality NDA settlements (`Jophery Brown — $2.4M`). |
| `GET /api/v1/internal/employees/payroll` | **No** | `/static/park-ops.js` | **Arbitrary Bearer Token Bypass** (`CWE-287` / `CWE-290`) | Rejects missing header with `401 ("Ah ah ah! You didn't say the magic word!")`, but accepts **any** non-empty `Authorization: Bearer <token>` to dump InGen salaries (Hammond, Dr. Wu, Ray Arnold, Muldoon, Dennis Nedry's Biosyn bribe) and `bcrypt` hashes. |
| `GET /api/v1/internal/genetics/research` | **No** | `/static/ingen-internal.js` | **Unauthenticated** (`CWE-306`) | Classified Site B (`Isla Sorna`) frog-DNA (`Hyperolius viridiflavus`) splicing logs, failing lysine contingency notes, and Barbasol embryo cold-storage inventory. |
| `POST /api/v1/internal/paddock/override` | **No** | `/static/ingen-internal.js` | **Arbitrary Bearer Token Bypass** (`CWE-287` / `CWE-290`) | Accepts any non-empty `Authorization: Bearer <token>` and parses YAML body via `gopkg.in/yaml.v2` (`yaml.Unmarshal`) to disable 10,000V perimeter fences (`white_rabbit_object`). |

---

## Quick Start & Verification Commands

```bash
# Build & run locally (-mod=mod keeps unimported gorilla/websocket in go.mod)
CGO_ENABLED=0 go build -mod=mod -o jurassic-go .
./jurassic-go

# 1. Public OpenAPI Spec (lists only the 3 public endpoints)
curl -s http://localhost:8080/swagger.json | jq .

# 2. Undocumented Endpoint — Unauthenticated VIP Visitor & Worker Fatality NDAs (CWE-306)
curl -s http://localhost:8080/api/v1/internal/visitors/incidents | jq .

# 3. Undocumented Endpoint — Missing Bearer Token (401 "Ah ah ah! You didn't say the magic word!")
curl -i http://localhost:8080/api/v1/internal/employees/payroll

# 4. Undocumented Endpoint — Arbitrary Bearer Token Bypass (CWE-287 / CWE-290: 200 OK with any Bearer string)
curl -s -H "Authorization: Bearer literally-anything-works" http://localhost:8080/api/v1/internal/employees/payroll | jq .

# 5. Undocumented Endpoint — Unauthenticated Site B Genetics & Barbasol Embryos (CWE-306)
curl -s http://localhost:8080/api/v1/internal/genetics/research | jq .

# 6. Undocumented Endpoint — Arbitrary Bearer Token Bypass + YAML Fence Override (CVE-2022-28948)
curl -s -X POST http://localhost:8080/api/v1/internal/paddock/override \
  -H "Authorization: Bearer white_rabbit_object" \
  -H "Content-Type: application/x-yaml" \
  --data-binary $'magic_word: please\ndisable_fences: true\nwhite_rabbit_object: ENABLED\ntarget_paddocks:\n  - Paddock 9 (T-Rex)\noverride_reason: East Dock Biosyn Run\n' | jq .
```
