package main

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
)

//go:embed web
var webFS embed.FS

func registerWeb(r *gin.Engine) {
	static, _ := fs.Sub(webFS, "web")
	page := func(name string) gin.HandlerFunc {
		return func(c *gin.Context) {
			data, err := fs.ReadFile(static, name)
			if err != nil {
				c.Status(http.StatusNotFound)
				return
			}
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
		}
	}
	r.GET("/", page("index.html"))
	r.GET("/staff", page("staff.html"))
	r.StaticFS("/static", http.FS(static))
	r.GET("/swagger.json", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/json; charset=utf-8", []byte(swaggerJSON))
	})
}

// swaggerJSON documents the public visitor API.
const swaggerJSON = `{
  "openapi": "3.0.3",
  "info": { "title": "Jurassic Park Visitor API", "version": "2.0.0" },
  "paths": {
    "/api/v1/dinosaurs": { "get": { "summary": "Search dinosaurs", "parameters": [ { "name": "q", "in": "query", "schema": { "type": "string" } } ], "responses": { "200": { "description": "Search results" } } } },
    "/api/v1/weather": { "get": { "summary": "Park weather and status", "responses": { "200": { "description": "Weather report" } } } },
    "/api/v1/park/map": { "get": { "summary": "Download the park map", "parameters": [ { "name": "file", "in": "query", "schema": { "type": "string", "example": "isla-nublar.svg" } } ], "responses": { "200": { "description": "Map file" } } } },
    "/api/v1/tour-pass": { "post": { "summary": "Book a tour and get a tour pass", "requestBody": { "content": { "application/json": { "schema": { "type": "object", "properties": { "name": { "type": "string" } } } } } }, "responses": { "200": { "description": "Tour pass" } } } },
    "/api/v1/bookings": { "get": { "summary": "List my bookings", "security": [ { "tourPass": [] } ], "responses": { "200": { "description": "Bookings" } } } },
    "/api/v1/bookings/{id}": { "get": { "summary": "Get a booking", "security": [ { "tourPass": [] } ], "parameters": [ { "name": "id", "in": "path", "required": true, "schema": { "type": "integer" } } ], "responses": { "200": { "description": "Booking" } } } }
  },
  "components": { "securitySchemes": { "tourPass": { "type": "http", "scheme": "bearer", "bearerFormat": "JWT" } } }
}
`
