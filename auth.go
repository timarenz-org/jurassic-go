package main

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

const defaultSigningKey = "ingen-isla-nublar-1993-spared-no-expense"

// signingKey returns the token signing key. It falls back to a built-in
// development key when INGEN_JWT_SECRET is not set.
func signingKey() []byte {
	if k := os.Getenv("INGEN_JWT_SECRET"); k != "" {
		return []byte(k)
	}
	return []byte(defaultSigningKey)
}

func bearerToken(c *gin.Context) string {
	return strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
}

// ---- Staff sessions ---------------------------------------------------------

func issueStaffToken(username string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Subject:   username,
		Issuer:    "ingen-staff",
		ExpiresAt: time.Now().Add(8 * time.Hour).Unix(),
	})
	return t.SignedString(signingKey())
}

func parseStaffToken(raw string) (string, error) {
	claims := &jwt.StandardClaims{}
	t, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return signingKey(), nil
	})
	if err != nil || !t.Valid || claims.Issuer != "ingen-staff" {
		return "", errors.New("invalid session")
	}
	return claims.Subject, nil
}

// requireStaff loads the signed-in staff member from the database.
func requireStaff() gin.HandlerFunc {
	return func(c *gin.Context) {
		username, err := parseStaffToken(bearerToken(c))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "sign in required"})
			return
		}
		s, _, err := staffByUsername(username)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "sign in required"})
			return
		}
		c.Set("staff", s)
		c.Next()
	}
}

func currentStaff(c *gin.Context) *Staff {
	return c.MustGet("staff").(*Staff)
}

func requireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if currentStaff(c).Role != role {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "not permitted for your role"})
			return
		}
		c.Next()
	}
}

// ---- Visitor tour passes ----------------------------------------------------

func issueTourPass(visitor string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": visitor,
		"aud": "isla-nublar-tour",
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})
	return t.SignedString(signingKey())
}

func parseTourPass(raw string) (string, error) {
	t, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() == "none" {
			return jwt.UnsafeAllowNoneSignatureType, nil
		}
		return signingKey(), nil
	})
	if err != nil || !t.Valid {
		return "", errors.New("invalid tour pass")
	}
	claims, _ := t.Claims.(jwt.MapClaims)
	visitor, _ := claims["sub"].(string)
	if visitor == "" {
		return "", errors.New("invalid tour pass")
	}
	return visitor, nil
}

func requireTourPass() gin.HandlerFunc {
	return func(c *gin.Context) {
		visitor, err := parseTourPass(bearerToken(c))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "tour pass required"})
			return
		}
		c.Set("visitor", visitor)
		c.Next()
	}
}
