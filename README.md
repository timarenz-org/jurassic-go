# 🦖 jurassic-go — Jurassic Park System

A small Jurassic Park web app. Visitors search dinosaurs, check the weather, download the park map, and book a tour. Staff sign in to manage the roster, export bookings, import feeding schedules, and (control room only) run the park systems.

The app is **intentionally vulnerable**. It is meant for security testing and training. Every weakness sits inside a feature the app actually uses.

> [!WARNING]
> Run it only in an isolated test environment with no real data or credentials.

## Run

```bash
CGO_ENABLED=0 go build -mod=mod -o jurassic-go . && ./jurassic-go   # http://localhost:8080
# or
docker build -t jurassic-go . && docker run -p 8080:8080 jurassic-go
```

Data lives in an embedded in-memory SQLite database and resets on restart.

## Pages

| Page | What it does |
| :--- | :--- |
| `/` | Visitor site: dinosaur search, weather, park map download, tour pass, My bookings |
| `/staff` | Staff sign-in and dashboard: profile, roster, bookings export, feeding-schedule import; Park systems for the control room |

## Test accounts

| Username | Password | Character | Role |
| :--- | :--- | :--- | :--- |
| `muldoon` | `clever-girl` | Robert Muldoon, game warden | `game_warden` (low privilege) |
| `arnold` | `hold-onto-your-butts` | John "Ray" Arnold, chief engineer | `control_room` |
| `nedry` | `whte-rbt-obj` | Dennis Nedry, systems programmer | `programmer` |

Visitors don't sign in. They get a tour pass by entering a name on `/`.

## API

| Route | Access | Feature |
| :--- | :--- | :--- |
| `GET /healthz` | Public | Health check (database and metrics exporter status) |
| `GET /api/v1/dinosaurs?q=` | Public | Dinosaur search |
| `GET /api/v1/weather` | Public | Weather (optional upstream feed via `EARTHWATCH_URL`) |
| `GET /api/v1/park/map?file=` | Public | Park map download |
| `POST /api/v1/tour-pass` | Public | Book a tour, get a tour pass |
| `GET /api/v1/bookings`, `GET /api/v1/bookings/:id` | Tour pass | My bookings |
| `POST /api/v1/staff/login` | Public | Staff sign-in |
| `GET/PATCH /api/v1/staff/me`, `GET /api/v1/staff/roster`, `GET /api/v1/staff/bookings/export`, `POST /api/v1/staff/feeding-schedule` | Staff | Staff dashboard |
| `GET /api/v1/systems/{power,fences,security}` | Staff | Park systems status |
| `POST /api/v1/systems/{power,fences}` | Staff, `control_room`, maintenance shed network | Park systems control |
| `POST /api/v1/systems/security` | Staff, `control_room` | Door locks and cameras |
| `GET/POST /api/v1/systems/cold-storage` | — | Embryo cold storage |

`/swagger.json` documents only the visitor API.

## Expected findings

### Vulnerable dependencies

| # | Package | CVE | How the app uses it |
| :-- | :--- | :--- | :--- |
| 1 | `github.com/dgrijalva/jwt-go` v3.2.0 | CVE-2020-26160 | Tour pass and staff session tokens |
| 2 | `gopkg.in/yaml.v3` v3.0.0-20210107192922 | CVE-2022-28948 | Feeding-schedule import |
| 3 | `github.com/gin-gonic/gin` v1.6.3 | CVE-2020-28483, CVE-2023-29401, CVE-2023-26125 | Web framework |
| 4 | `github.com/microcosm-cc/bluemonday` v1.0.4 | CVE-2021-42576, CVE-2021-29272 | Imported but never called |
| 5 | `golang.org/x/crypto` (2020-07-09) | CVE-2024-45337 and other `ssh` CVEs | Only `bcrypt` is used; `ssh` is not imported |
| 6 | `golang.org/x/text` v0.3.3 | CVE-2021-38561, CVE-2022-32149 | Only `transform` is used; `language` is not imported |
| 7 | `github.com/klauspost/compress` v1.9.5 | CVE-2026-63209 | Only `zstd` is used; `s2` is not imported |
| 8 | `github.com/gorilla/websocket` v1.4.0 | CVE-2020-27813 | Listed in `go.mod` only; not in the binary |
| 9 | Go 1.21 standard library | various | Container image runtime |

### Weaknesses in the application code

| # | Weakness | CWE | Feature | Access |
| :-- | :--- | :--- | :--- | :--- |
| 10 | SQL injection | CWE-89 | Dinosaur search | Public |
| 11 | Path traversal | CWE-22 | Park map download | Public |
| 12 | Insecure TLS client configuration | CWE-327 | Weather feed | Public |
| 13 | Cleartext HTTP, no server timeouts | CWE-319, CWE-400 | Server startup | All |
| 14 | Missing authentication (route registered outside the staff group) | CWE-306 | Embryo cold storage | Public |
| 15 | Undocumented API (staff routes not in `/swagger.json`) | CWE-1059 | Staff and park systems routes | Public |
| 16 | Unsigned tour pass accepted | CWE-347 | Tour pass | Visitor |
| 17 | Insecure direct object reference | CWE-639 | Booking detail | Visitor |
| 18 | Mass assignment of the role field | CWE-915 | Staff profile update | Staff |
| 19 | Network allowlist trusts a client header | CWE-290 | Power and fence control | Staff (control room) |
| 20 | Hidden functionality (`whte_rbt.obj`) | CWE-912 | Feeding-schedule import | Staff |
| 21 | Hard-coded override word | CWE-798 | Re-arming fences | Staff (control room) |
| 22 | Hard-coded signing key fallback | CWE-798 | Session and tour pass signing | — |
| 23 | Hard-coded cloud credentials exposed in the health check (fake AWS key) | CWE-798, CWE-200 | Health check | Public |

Staff sessions are verified properly (HS256 only, role read from the database).
