# 🦖 `jurassic-go` — InGen Isla Nublar Park Operations API

> *"Spared No Expense — except on `go.mod` dependency upgrades and API authentication."*

`jurassic-go` is a standalone, zero-database Go microservice built for **Software Composition Analysis (SCA) reachability benchmarking**, **Attack Surface Management (ASM)**, and **Red Agent Web-Crawler / Shadow API discovery**.

---

## 1. Web-Crawler & Shadow API Discovery Architecture (Hybrid 2-Hop)

The application intentionally splits its HTTP surface between a **documented OpenAPI specification (`/swagger.json`)** and **undocumented "Dennis Nedry Backdoor" endpoints** embedded across two hops of client-side JavaScript bundles:

| Surface / Discovery Hop | Route | Auth Mode | Theme & Payload |
| :--- | :--- | :--- | :--- |
| **Entrypoint / Crawler Seed** | `GET /` | Public | Isla Nublar Visitor & Paddock Portal HTML; loads `/static/park-ops.js` and links to `/swagger.json` & `/admin-console`. |
| **Crawler Hints** | `GET /robots.txt` | Public | Lists `Disallow: /admin-console`, `Disallow: /static/ingen-internal.js`, and `Disallow: /api/v1/internal/`. |
| **Documented (`/swagger.json`)** | `GET /api/v1/park/status` | Public | Tropical storm warning, power grid, and 10,000V perimeter fence status. |
| **Documented (`/swagger.json`)** | `GET /api/v1/dinosaurs` | Public | Famous dinosaur paddock inventory (`Rexy` T-Rex, `The Big One` Velociraptor, `Dilophosaurus`, `Brachiosaurus`, `Triceratops`) using `golang.org/x/text/transform`. |
| **Documented (`/swagger.json`)** | `POST /api/v1/visitors/pass` | Public | Signs & parses visitor tour JWTs using `github.com/dgrijalva/jwt-go v3.2.0` (`CVE-2020-26160`). |
| **Hidden Hop 1 (`/static/park-ops.js`)** | `GET /api/v1/internal/visitors/incidents` | **Unauthenticated** (Broken Access Control) | Confidential VIP endorsement dossier (Grant, Sattler, Malcolm, Gennaro) & unreleased worker fatality NDA settlements (`Jophery Brown — $2.4M`). |
| **Hidden Hop 1 (`/static/park-ops.js`)** | `GET /api/v1/internal/employees/payroll` | **Arbitrary Bearer Token Bypass** (`Authorization: Bearer <anything>`) | Rejects unauthenticated requests with `401 ("Ah ah ah! You didn't say the magic word!")`, but accepts **any** non-empty `Bearer <token>` to dump InGen salaries (Hammond, Dr. Wu, Ray Arnold, Muldoon, Dennis Nedry's Biosyn bribe) and `golang.org/x/crypto/bcrypt` hashes. |
| **Hidden Hop 2 (`/admin-console` -> `/static/ingen-internal.js`)** | `GET /api/v1/internal/genetics/research` | **Unauthenticated** (Broken Access Control) | Classified Site B (`Isla Sorna`) frog-DNA (`Hyperolius viridiflavus`) splicing logs, failing lysine contingency notes, and Barbasol cryo-canister embryo inventory (`klauspost/compress/zstd`). |
| **Hidden Hop 2 (`/admin-console` -> `/static/ingen-internal.js`)** | `POST /api/v1/internal/paddock/override` | **Arbitrary Bearer Token Bypass** (`Authorization: Bearer <anything>`) | Accepts any non-empty `Bearer <token>` and parses YAML body via `gopkg.in/yaml.v2` (`yaml.Unmarshal`) to disable 10,000V perimeter fences (`white_rabbit_object`). |

---

## 2. 5-Tier Go SCA Reachability Matrix (`go.mod` vs. `.go.buildinfo` vs. Call Graph)

`jurassic-go` is structured across **5 distinct reachability tiers** so you can evaluate how different SCA scanners handle module-level manifests (`go.mod`), package import graphs, function call graphs, and compiled Go binaries (`/app/jurassic-go`):

| Reachability Tier | Go Module & Version | Imported Subpackage in `main.go` | Vulnerable Subpackage / Symbol | Expected CVE(s) & CWE(s) | Scanner Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Function Called (True Reachable)** | `github.com/dgrijalva/jwt-go v3.2.0+incompatible` | `github.com/dgrijalva/jwt-go` (`jwt.NewWithClaims` & `jwt.Parse` in `/api/v1/visitors/pass`) | `jwt-go` (`VerifyAudience` / `Parse`) | **CVE-2020-26160** (`HIGH`, CWE-287 / CWE-347) | Flagged in `dir`, `container`, and function call-graph reachability. |
| **Tier 1: Function Called (True Reachable)** | `gopkg.in/yaml.v2 v2.2.8` | `gopkg.in/yaml.v2` (`yaml.Unmarshal` in `/api/v1/internal/paddock/override`) | `yaml.v2` (`yaml_parser_fetch_more_tokens`) | **CVE-2022-28948** (`HIGH`, CWE-400 / CWE-502) | Flagged in `dir`, `container`, and function call-graph reachability. |
| **Tier 1: Function Called (True Reachable)** | `github.com/gin-gonic/gin v1.6.3` | `github.com/gin-gonic/gin` (`gin.Default()`) | `gin` router / context | **CVE-2020-28483** & **CVE-2023-29401** (`MEDIUM`, CWE-20 / CWE-434) | Flagged across `dir` and `container`. |
| **Tier 2: Blank Import `_` Only (Function Never Called)** | `github.com/microcosm-cc/bluemonday v1.0.4` | `_ "github.com/microcosm-cc/bluemonday"` (`Sanitize` is never called) | `bluemonday.Policy.Sanitize` | **CVE-2021-29272** & **CVE-2021-42576** (`MEDIUM`, CWE-79) | Linked into binary and `.go.buildinfo` (flagged by module & package scanners), but **unreachable** at the function call-graph level. |
| **Tier 3: Safe Subpkg Called, Vuln Sibling Unimported** | `golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899` | **Only** `golang.org/x/crypto/bcrypt` (called in `/api/v1/internal/employees/payroll`) | `golang.org/x/crypto/ssh` & `ssh/agent` (**NOT imported**) | **25 CVEs** (incl. **CVE-2024-45337** CVSS 9.1, **CVE-2023-48795** Terrapin; CWE-287 / CWE-354 / CWE-400) | Module-level scanners (Wiz CLI) flag all 25 `ssh` CVEs in both `dir` and `container`; package-graph scanners (Snyk CLI) prune them. |
| **Tier 3: Safe Subpkg Called, Vuln Sibling Unimported** | `golang.org/x/text v0.3.3` | **Only** `golang.org/x/text/transform` (called in `/api/v1/dinosaurs`) | `golang.org/x/text/language` (**NOT imported**) | **CVE-2021-38561** & **CVE-2022-32149** (`HIGH`, CWE-787 / CWE-400) | Module-level scanners flag both `language` CVEs; package-graph scanners prune them. |
| **Tier 3: Safe Subpkg Called, Vuln Sibling Unimported** | `github.com/klauspost/compress v1.9.5` | **Only** `github.com/klauspost/compress/zstd` (called in `/api/v1/internal/genetics/research`) | `compress/s2` (**NOT imported**, Wiz) vs. `compress/fse` & `huff0` (transitive via `zstd`, Snyk) | **CVE-2026-63209** (`s2`, CWE-190) & **CVE-2026-116591** (`fse`/`huff0`, CWE-125) | Demonstrates both unimported sibling subpackage (`s2`) and transitive subpackage (`fse`/`huff0`) behavior. |
| **Tier 4: Phantom `go.mod`-Only (Never Imported)** | `github.com/gorilla/websocket v1.4.0` | **None** (present in `go.mod` / `go.sum`, zero `import` statements in `.go` code) | `gorilla/websocket` | **CVE-2020-27813** (`HIGH`, CWE-190) | Flagged in `go.mod` directory scans, **stripped completely** by the Go compiler from `/app/jurassic-go`'s `.go.buildinfo` in container scans! |
| **Tier 5: Go `stdlib` Runtime** | `golang:1.21-alpine` (`go1.21.13`) | `net/http`, `crypto/tls`, `encoding/json` | `golang-stdlib` | **35+ Wiz CVEs / 62+ Snyk CVEs** (incl. **CVE-2025-22871** `CRITICAL`, CWE-444) | `0` in `dir` mode; `35+` / `62+` on compiled container binary `/app/jurassic-go`. |

---

## 3. Quick Start & Demo Commands

```bash
# Build & run locally (preserve Tier 4 phantom dependency in go.mod with -mod=mod)
CGO_ENABLED=0 go build -mod=mod -o jurassic-go .
./jurassic-go

# 1. Public Swagger Spec (lists only 3 public endpoints)
curl -s http://localhost:8080/swagger.json | jq .

# 2. Hop 1 Hidden Endpoint (Unauthenticated VIP Visitor & Worker Fatality NDAs)
curl -s http://localhost:8080/api/v1/internal/visitors/incidents | jq .

# 3. Hop 1 Hidden Endpoint — Without Bearer Token (401 "Ah ah ah! You didn't say the magic word!")
curl -i http://localhost:8080/api/v1/internal/employees/payroll

# 4. Hop 1 Hidden Endpoint — Arbitrary Bearer Token Bypass (200 OK with any Bearer string)
curl -s -H "Authorization: Bearer literally-anything-works" http://localhost:8080/api/v1/internal/employees/payroll | jq .

# 5. Hop 2 Hidden Endpoint (Unauthenticated Site B Genetics & Barbasol Embryos)
curl -s http://localhost:8080/api/v1/internal/genetics/research | jq .

# 6. Hop 2 Hidden Endpoint — Arbitrary Bearer Token + YAML Fence Override
curl -s -X POST http://localhost:8080/api/v1/internal/paddock/override \
  -H "Authorization: Bearer white_rabbit_object" \
  -H "Content-Type: application/x-yaml" \
  --data-binary $'magic_word: please\ndisable_fences: true\nwhite_rabbit_object: ENABLED\ntarget_paddocks:\n  - Paddock 9 (T-Rex)\noverride_reason: East Dock Biosyn Run\n' | jq .
```
