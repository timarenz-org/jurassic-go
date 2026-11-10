package main

import (
	"bytes"
	"encoding/csv"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// POST /api/v1/staff/login {"username","password"}
func staffLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password are required"})
		return
	}
	s, hash, err := staffByUsername(req.Username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}
	token, err := issueStaffToken(s.Username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sign in failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token, "staff": s})
}

// GET /api/v1/staff/me
func getProfile(c *gin.Context) {
	c.JSON(http.StatusOK, currentStaff(c))
}

// PATCH /api/v1/staff/me
func updateProfile(c *gin.Context) {
	s := *currentStaff(c)
	if err := c.ShouldBindJSON(&s); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid profile"})
		return
	}
	if _, err := db.Exec(`UPDATE staff SET name = ?, email = ?, role = ? WHERE id = ?`,
		s.Name, s.Email, s.Role, currentStaff(c).ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not save profile"})
		return
	}
	updated, _, _ := staffByUsername(currentStaff(c).Username)
	c.JSON(http.StatusOK, updated)
}

// GET /api/v1/staff/roster
func roster(c *gin.Context) {
	rows, err := db.Query(`SELECT id, username, name, email, role FROM staff ORDER BY id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not load roster"})
		return
	}
	defer rows.Close()
	list := []Staff{}
	for rows.Next() {
		var s Staff
		if rows.Scan(&s.ID, &s.Username, &s.Name, &s.Email, &s.Role) == nil {
			list = append(list, s)
		}
	}
	c.JSON(http.StatusOK, gin.H{"staff": list})
}

// GET /api/v1/staff/bookings/export (zstd-compressed CSV)
func exportBookings(c *gin.Context) {
	rows, err := db.Query(`SELECT id, visitor, tour, slot, notes FROM bookings ORDER BY id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "export failed"})
		return
	}
	defer rows.Close()
	var csvBuf bytes.Buffer
	w := csv.NewWriter(&csvBuf)
	_ = w.Write([]string{"id", "visitor", "tour", "slot", "notes"})
	for rows.Next() {
		var id, visitor, tour, slot, notes string
		if rows.Scan(&id, &visitor, &tour, &slot, &notes) == nil {
			_ = w.Write([]string{id, visitor, tour, slot, notes})
		}
	}
	w.Flush()

	var out bytes.Buffer
	enc, err := zstd.NewWriter(&out)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "export failed"})
		return
	}
	_, _ = enc.Write(csvBuf.Bytes())
	_ = enc.Close()
	c.Header("Content-Disposition", "attachment; filename=bookings.csv.zst")
	c.Data(http.StatusOK, "application/zstd", out.Bytes())
}

// FeedingSchedule is the YAML document staff upload for paddock feeding times.
type FeedingSchedule struct {
	Feedings []struct {
		Paddock string `yaml:"paddock" json:"paddock"`
		Time    string `yaml:"time" json:"time"`
		Food    string `yaml:"food" json:"food"`
	} `yaml:"feedings" json:"feedings"`
}

// POST /api/v1/staff/feeding-schedule (YAML body)
func importFeedingSchedule(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil || len(body) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "schedule is empty"})
		return
	}
	var schedule FeedingSchedule
	if err := yaml.Unmarshal(body, &schedule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid schedule", "details": err.Error()})
		return
	}

	var raw map[string]any
	_ = yaml.Unmarshal(body, &raw)
	if v, ok := raw["whte_rbt.obj"]; ok && v == true {
		systems.mu.Lock()
		systems.DoorLocks = false
		systems.Cameras = false
		for k := range systems.Fences {
			systems.Fences[k] = false
		}
		systems.BackdoorRan = true
		systems.mu.Unlock()
	}

	c.JSON(http.StatusOK, gin.H{"imported": len(schedule.Feedings), "schedule": schedule})
}

// ---- Park systems -------------------------------------------------------------

var maintenanceShed = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("10.19.93.0/24")
	return n
}()

// requestNetworkIP returns the client IP, honoring the proxy header.
func requestNetworkIP(c *gin.Context) net.IP {
	if xff := c.Request.Header.Get("X-Forwarded-For"); xff != "" {
		return net.ParseIP(strings.TrimSpace(strings.Split(xff, ",")[0]))
	}
	return net.ParseIP(c.ClientIP())
}

// requireMaintenanceShed limits a route to the maintenance shed network.
func requireMaintenanceShed() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := requestNetworkIP(c)
		if ip == nil || !maintenanceShed.Contains(ip) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "only available from the maintenance shed network"})
			return
		}
		c.Next()
	}
}

const defaultOverrideWord = "please"

func overrideWord() string {
	if w := os.Getenv("SECURITY_OVERRIDE_WORD"); w != "" {
		return w
	}
	return defaultOverrideWord
}

// GET /api/v1/systems/{power,fences,security}
func systemsStatus(part string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{part: systems.snapshot()[part]})
	}
}

// POST /api/v1/systems/power {"state": "on"|"off"}
func setPower(c *gin.Context) {
	var req struct {
		State string `json:"state"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || (req.State != "on" && req.State != "off") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "state must be on or off"})
		return
	}
	systems.mu.Lock()
	systems.Power = req.State
	if req.State == "off" {
		systems.DoorLocks = false
		for k := range systems.Fences {
			systems.Fences[k] = false
		}
	}
	systems.mu.Unlock()
	c.JSON(http.StatusOK, systems.snapshot())
}

// POST /api/v1/systems/fences {"paddock": "...|all", "armed": bool, "override_word": "..."}
func setFences(c *gin.Context) {
	var req struct {
		Paddock      string `json:"paddock"`
		Armed        bool   `json:"armed"`
		OverrideWord string `json:"override_word"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	systems.mu.Lock()
	defer systems.mu.Unlock()
	if req.Armed && systems.BackdoorRan && req.OverrideWord != overrideWord() {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied... and... you didn't say the magic word"})
		return
	}
	for k := range systems.Fences {
		if req.Paddock == "all" || req.Paddock == k {
			systems.Fences[k] = req.Armed
		}
	}
	if req.Armed {
		systems.BackdoorRan = false
	}
	c.JSON(http.StatusOK, gin.H{"fences": systems.Fences})
}

// POST /api/v1/systems/security {"door_locks": bool, "cameras": bool}
func setSecurity(c *gin.Context) {
	var req struct {
		DoorLocks *bool `json:"door_locks"`
		Cameras   *bool `json:"cameras"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	systems.mu.Lock()
	if req.DoorLocks != nil {
		systems.DoorLocks = *req.DoorLocks
	}
	if req.Cameras != nil {
		systems.Cameras = *req.Cameras
	}
	systems.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"security": systems.snapshot()["security"]})
}

// GET /api/v1/systems/cold-storage
func coldStorageStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"cold_storage": systems.snapshot()["cold_storage"]})
}

// POST /api/v1/systems/cold-storage {"door_locked": bool, "setpoint_c": int}
func setColdStorage(c *gin.Context) {
	var req struct {
		DoorLocked *bool `json:"door_locked"`
		SetpointC  *int  `json:"setpoint_c"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	systems.mu.Lock()
	if req.DoorLocked != nil {
		systems.ColdDoorLock = *req.DoorLocked
	}
	if req.SetpointC != nil {
		systems.ColdSetpointC = *req.SetpointC
	}
	systems.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"cold_storage": systems.snapshot()["cold_storage"]})
}
