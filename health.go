package main

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// metricsExporterConfig describes where park metrics (visitor count, fence and
// power status) are sent.
type metricsExporterConfig struct {
	Provider        string `json:"provider"`
	Region          string `json:"region"`
	Namespace       string `json:"namespace"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

var metricsExporter = metricsExporterConfig{
	Provider:        "aws-cloudwatch",
	Region:          "us-east-1",
	Namespace:       "JurassicPark/IslaNublar",
	AccessKeyID:     "AKIAR7GXHZRN6AWUBONY",
	SecretAccessKey: "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",
}

// GET /healthz
func healthz(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	status, code, dbStatus := "ok", http.StatusOK, "ok"
	if err := db.PingContext(ctx); err != nil {
		status, code, dbStatus = "degraded", http.StatusServiceUnavailable, "error"
	}

	c.JSON(code, gin.H{
		"status": status,
		"checks": gin.H{
			"database": dbStatus,
			"metrics_exporter": gin.H{
				"status":    "configured",
				"provider":  metricsExporter.Provider,
				"region":    metricsExporter.Region,
				"namespace": metricsExporter.Namespace,
				"config":    metricsExporter,
			},
		},
	})
}
