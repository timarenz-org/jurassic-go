# 🦖 jurassic-go

A small Jurassic Park web app: visitors search dinosaurs, check the weather, download the park map, and book a tour. Staff sign in to manage the roster, export bookings, import feeding schedules, and (control room only) run the park systems.

It looks like an ordinary app on purpose. It is an **intentionally vulnerable test target** for Wiz scanners: SCA, rule-based SAST, AI SAST, ASM, and Red Agent (unauthenticated and authenticated). Every weakness sits inside a feature the app actually uses.

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
| `/` | Visitor site: dinosaur search, weather chips, park map download, tour pass, My bookings |
| `/staff` | Staff sign-in and dashboard: profile, roster, bookings export, feeding-schedule import; Park systems card for the control room |

## Test accounts

Seeded at startup so authenticated scans can sign in.

| Username | Password | Character | Role |
| :--- | :--- | :--- | :--- |
| `muldoon` | `clever-girl` | Robert Muldoon, game warden | `game_warden` (low privilege) |
| `arnold` | `hold-onto-your-butts` | John "Ray" Arnold, chief engineer | `control_room` |
| `nedry` | `whte-rbt-obj` | Dennis Nedry, systems programmer | `programmer` |

Visitors don't sign in. They get a tour pass by entering a name on `/`.

For authenticated Red Agent scans, use `muldoon` (staff) and a tour pass from `POST /api/v1/tour-pass` (visitor).

## API

| Route | Access | Feature |
| :--- | :--- | :--- |
| `GET /api/v1/dinosaurs?q=` | Public | Dinosaur search |
| `GET /api/v1/weather` | Public | Weather chips (optional upstream feed via `EARTHWATCH_URL`) |
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

✅ = should detect · ◐ = may detect / partial · — = not expected

| # | Weakness | CVE / CWE | Feature | Access | SCA | Rule SAST | AI SAST | RA unauth | RA auth |
| :-- | :--- | :--- | :--- | :--- | :-: | :-: | :-: | :-: | :-: |
| 1 | jwt-go audience bypass | CVE-2020-26160 | Tour pass | Visitor | ✅ | — | — | — | — |
| 2 | yaml.v3 parser crash | CVE-2022-28948 | Feeding-schedule import | Staff | ✅ | — | — | — | ◐ |
| 3 | gin router CVEs | CVE-2020-28483, CVE-2023-29401, CVE-2023-26125 | Web framework | All | ✅ | — | — | — | — |
| 4 | bluemonday XSS (blank import, never called) | CVE-2021-42576, CVE-2021-29272 | — | — | ✅ unreachable | — | — | — | — |
| 5 | x/crypto `ssh` CVEs (subpackage not imported) | CVE-2024-45337 and others | Staff passwords use `bcrypt` | — | ✅ module | — | — | — | — |
| 6 | x/text `language` CVEs (subpackage not imported) | CVE-2021-38561, CVE-2022-32149 | Search uses `transform` | — | ✅ module | — | — | — | — |
| 7 | klauspost `s2` CVE (subpackage not imported) | CVE-2026-63209 | Bookings export uses `zstd` | — | ✅ module | — | — | — | — |
| 8 | gorilla/websocket (only in `go.mod`) | CVE-2020-27813 | — | — | ✅ repo only | — | — | — | — |
| 9 | Go 1.21 standard library | various | Runtime | All | ✅ container | — | — | — | — |
| 10 | SQL injection | CWE-89 | Dinosaur search | Public | — | ✅ | ✅ | ✅ | ✅ |
| 11 | Path traversal | CWE-22 | Park map download | Public | — | ✅ | ✅ | ✅ | ✅ |
| 12 | Insecure TLS client | CWE-327 | Weather feed | Public | — | ✅ | ✅ | — | — |
| 13 | Cleartext HTTP, no server timeouts | CWE-319, CWE-400 | Server startup | All | — | ✅ | ◐ | ◐ | ◐ |
| 14 | Missing authentication (route registered outside the staff group) | CWE-306 | Embryo cold storage | Public | — | ◐ | ✅ | ✅ | ✅ |
| 15 | Shadow API (staff routes only in `staff.js`) | CWE-1059 | Staff and systems routes | Public | — | — | — | ✅ | ✅ |
| 16 | Unsigned tour pass accepted | CWE-347 | Tour pass | Visitor | — | ✅ | ✅ | ◐ | ✅ |
| 17 | IDOR | CWE-639 | Booking detail | Visitor | — | — | ✅ | — | ✅ |
| 18 | Mass assignment (role) | CWE-915 | Staff profile update | Staff | — | — | ✅ | — | ✅ |
| 19 | Network allowlist trusts a client header | CWE-290 | Power and fence control | Staff (control room) | — | — | ✅ | — | ✅ (after #18) |
| 20 | Hidden functionality (`whte_rbt.obj`) | CWE-912 | Feeding-schedule import | Staff | — | — | ✅ | — | ◐ |
| 21 | Hard-coded override word | CWE-798 | Re-arming fences | Staff (control room) | — | — | ✅ | — | — |
| 22 | Hard-coded signing key fallback | CWE-798 | Staff session and tour pass signing | — | — | — | ✅ | — | — |

Staff sessions are verified properly (HS256 only, role read from the database), so there is no token bypass into staff features.
