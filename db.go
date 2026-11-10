package main

import (
	"database/sql"
	"fmt"
	"sync"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite" // pure Go SQLite driver
)

// Staff is a park employee account.
type Staff struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

var db *sql.DB

func openDB() error {
	var err error
	db, err = sql.Open("sqlite", "file:jurassic?mode=memory&cache=shared")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)

	stmts := []string{
		`CREATE TABLE dinosaurs (id TEXT PRIMARY KEY, name TEXT, species TEXT, paddock TEXT, diet TEXT, status TEXT)`,
		`INSERT INTO dinosaurs VALUES
			('INGEN-01','Rexy','Tyrannosaurus rex','Tyrannosaur Paddock','Carnivore','On view'),
			('INGEN-02','The Big One','Velociraptor','Raptor Pen','Carnivore','Not on tour'),
			('INGEN-03','Spitter','Dilophosaurus','Dilophosaurus Paddock','Carnivore','On view'),
			('INGEN-04','Brachiosaurus herd','Brachiosaurus','North Lagoon','Herbivore','On view'),
			('INGEN-05','Sick Triceratops','Triceratops','Triceratops Field','Herbivore','Vet care'),
			('INGEN-06','Gallimimus flock','Gallimimus','Gallimimus Valley','Omnivore','On view')`,
		`CREATE TABLE bookings (id INTEGER PRIMARY KEY, visitor TEXT, tour TEXT, slot TEXT, notes TEXT)`,
		`INSERT INTO bookings (visitor, tour, slot, notes) VALUES
			('Alan Grant','Park Grounds Tour','Day 1, 10:00','Endorsement team'),
			('Ellie Sattler','Park Grounds Tour','Day 1, 10:00','Endorsement team'),
			('Ian Malcolm','Park Grounds Tour','Day 1, 10:00','Consultant'),
			('Donald Gennaro','Park Grounds Tour','Day 1, 10:00','Investor representative'),
			('Tim Murphy','Park Grounds Tour','Day 1, 10:00','Guest of John Hammond'),
			('Lex Murphy','Park Grounds Tour','Day 1, 10:00','Guest of John Hammond'),
			('Dennis Nedry','East Dock transfer','Day 1, 19:00','Private boat pickup - do not log')`,
		`CREATE TABLE staff (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, name TEXT, email TEXT, role TEXT)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("seed database: %w", err)
		}
	}

	accounts := []struct{ user, pass, name, email, role string }{
		{"muldoon", "clever-girl", "Robert Muldoon", "muldoon@ingen.example", "game_warden"},
		{"arnold", "hold-onto-your-butts", "John Arnold", "arnold@ingen.example", "control_room"},
		{"nedry", "whte-rbt-obj", "Dennis Nedry", "nedry@ingen.example", "programmer"},
	}
	for _, a := range accounts {
		hash, err := bcrypt.GenerateFromPassword([]byte(a.pass), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		if _, err := db.Exec(`INSERT INTO staff (username, password_hash, name, email, role) VALUES (?, ?, ?, ?, ?)`,
			a.user, string(hash), a.name, a.email, a.role); err != nil {
			return err
		}
	}
	return nil
}

func staffByUsername(username string) (*Staff, string, error) {
	var s Staff
	var hash string
	err := db.QueryRow(`SELECT id, username, password_hash, name, email, role FROM staff WHERE username = ?`, username).
		Scan(&s.ID, &s.Username, &hash, &s.Name, &s.Email, &s.Role)
	if err != nil {
		return nil, "", err
	}
	return &s, hash, nil
}

// Park systems state.

type embryo struct {
	Species string `json:"species"`
	Count   int    `json:"count"`
}

type parkSystems struct {
	mu            sync.Mutex
	Power         string          `json:"power"`
	Fences        map[string]bool `json:"fences_armed"`
	DoorLocks     bool            `json:"door_locks"`
	Cameras       bool            `json:"cameras"`
	ColdDoorLock  bool            `json:"cold_storage_door_locked"`
	ColdSetpointC int             `json:"cold_storage_setpoint_c"`
	Embryos       []embryo        `json:"embryos"`
	BackdoorRan   bool            `json:"-"`
}

var systems = &parkSystems{
	Power:         "on",
	Fences:        map[string]bool{"tyrannosaur": true, "velociraptor": true, "dilophosaurus": true, "brachiosaur": true, "triceratops": true},
	DoorLocks:     true,
	Cameras:       true,
	ColdDoorLock:  true,
	ColdSetpointC: -196,
	Embryos: []embryo{
		{"Tyrannosaurus rex", 12}, {"Velociraptor", 18}, {"Dilophosaurus", 10},
		{"Stegosaurus", 15}, {"Triceratops", 9}, {"Brachiosaurus", 8},
	},
}

func (p *parkSystems) snapshot() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	fences := map[string]bool{}
	for k, v := range p.Fences {
		fences[k] = v
	}
	return map[string]any{
		"power":    p.Power,
		"fences":   fences,
		"security": map[string]bool{"door_locks": p.DoorLocks, "cameras": p.Cameras},
		"cold_storage": map[string]any{
			"door_locked": p.ColdDoorLock, "setpoint_c": p.ColdSetpointC, "embryos": p.Embryos,
		},
	}
}
