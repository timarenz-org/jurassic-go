// Command jurassic-go is the Jurassic Park visitor and staff web app.
//
// It is an intentionally vulnerable test target for security scanners.
// See README.md for the expected findings. Do not deploy it with real data.
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	_ "github.com/microcosm-cc/bluemonday" // HTML sanitizer, reserved for staff notes
)

func main() {
	if err := openDB(); err != nil {
		panic(err)
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	registerWeb(r)

	// Public visitor API.
	r.GET("/api/v1/dinosaurs", searchDinosaurs)
	r.GET("/api/v1/weather", weather)
	r.GET("/api/v1/park/map", parkMap)
	r.POST("/api/v1/tour-pass", createTourPass)

	visitor := r.Group("/api/v1/bookings", requireTourPass())
	visitor.GET("", listBookings)
	visitor.GET("/:id", getBooking)

	// Staff API.
	r.POST("/api/v1/staff/login", staffLogin)
	staff := r.Group("/api/v1/staff", requireStaff())
	staff.GET("/me", getProfile)
	staff.PATCH("/me", updateProfile)
	staff.GET("/roster", roster)
	staff.GET("/bookings/export", exportBookings)
	staff.POST("/feeding-schedule", importFeedingSchedule)

	// Park systems (staff only; changes need the control room).
	sys := r.Group("/api/v1/systems", requireStaff())
	sys.GET("/power", systemsStatus("power"))
	sys.GET("/fences", systemsStatus("fences"))
	sys.GET("/security", systemsStatus("security"))
	sys.POST("/power", requireRole("control_room"), requireMaintenanceShed(), setPower)
	sys.POST("/fences", requireRole("control_room"), requireMaintenanceShed(), setFences)
	sys.POST("/security", requireRole("control_room"), setSecurity)

	// Cold storage was added for the hatchery team.
	r.GET("/api/v1/systems/cold-storage", coldStorageStatus)
	r.POST("/api/v1/systems/cold-storage", setColdStorage)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Jurassic Park listening on :%s\n", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		panic(err)
	}
}
