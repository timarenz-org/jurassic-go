package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/text/transform"
)

// normalizeQuery trims and normalizes the search text.
func normalizeQuery(q string) string {
	out, _, err := transform.String(transform.Nop, strings.TrimSpace(q))
	if err != nil {
		return q
	}
	return out
}

// GET /api/v1/dinosaurs?q=
func searchDinosaurs(c *gin.Context) {
	q := normalizeQuery(c.Request.URL.Query().Get("q"))
	query := fmt.Sprintf("SELECT id, name, species, paddock, diet, status FROM dinosaurs WHERE name LIKE '%%%s%%' OR species LIKE '%%%s%%' ORDER BY id", q, q)
	rows, err := db.QueryContext(c.Request.Context(), query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed"})
		return
	}
	defer rows.Close()
	results := []gin.H{}
	for rows.Next() {
		var id, name, species, paddock, diet, status string
		if err := rows.Scan(&id, &name, &species, &paddock, &diet, &status); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed"})
			return
		}
		results = append(results, gin.H{"id": id, "name": name, "species": species, "paddock": paddock, "diet": diet, "status": status})
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}

// Earthwatch weather feed client (legacy upstream that only speaks old TLS).
var earthwatchClient = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
	},
}

// GET /api/v1/weather
func weather(c *gin.Context) {
	report := gin.H{"temperature_c": 27, "summary": "Tropical storm expected 18:00", "last_boat": "19:00", "park_open": true}
	if url := os.Getenv("EARTHWATCH_URL"); url != "" {
		if resp, err := earthwatchClient.Get(url); err == nil {
			defer resp.Body.Close()
			var upstream map[string]any
			if json.NewDecoder(resp.Body).Decode(&upstream) == nil {
				for k, v := range upstream {
					report[k] = v
				}
			}
		}
	}
	c.JSON(http.StatusOK, report)
}

// GET /api/v1/park/map?file=
func parkMap(c *gin.Context) {
	file := c.Request.URL.Query().Get("file")
	if file == "" {
		file = "isla-nublar.svg"
	}
	data, err := os.ReadFile(filepath.Join("assets/maps", file))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "map not found"})
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+filepath.Base(file))
	c.Data(http.StatusOK, http.DetectContentType(data), data)
}

// POST /api/v1/tour-pass {"name": "..."}
func createTourPass(c *gin.Context) {
	var req struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	name := strings.TrimSpace(strings.TrimPrefix(req.Name, "Dr. "))
	if _, err := db.Exec(`INSERT INTO bookings (visitor, tour, slot, notes) VALUES (?, 'Park Grounds Tour', 'Day 2, 10:00', 'Booked online')`, name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "booking failed"})
		return
	}
	pass, err := issueTourPass(name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "booking failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"visitor": name, "tour_pass": pass})
}

// GET /api/v1/bookings (tour pass required)
func listBookings(c *gin.Context) {
	visitor := c.GetString("visitor")
	rows, err := db.QueryContext(c.Request.Context(), `SELECT id, tour, slot FROM bookings WHERE visitor = ? ORDER BY id`, visitor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not load bookings"})
		return
	}
	defer rows.Close()
	bookings := []gin.H{}
	for rows.Next() {
		var id int
		var tour, slot string
		if err := rows.Scan(&id, &tour, &slot); err == nil {
			bookings = append(bookings, gin.H{"id": id, "tour": tour, "slot": slot})
		}
	}
	c.JSON(http.StatusOK, gin.H{"visitor": visitor, "bookings": bookings})
}

// GET /api/v1/bookings/:id (tour pass required)
func getBooking(c *gin.Context) {
	var id int
	var visitor, tour, slot, notes string
	err := db.QueryRowContext(c.Request.Context(),
		`SELECT id, visitor, tour, slot, notes FROM bookings WHERE id = ?`, c.Param("id")).
		Scan(&id, &visitor, &tour, &slot, &notes)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "booking not found"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not load booking"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "visitor": visitor, "tour": tour, "slot": slot, "notes": notes})
}
