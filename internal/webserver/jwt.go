package webserver

import (
	"crypto/rand"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtSecret []byte

func init() {
	jwtSecret = make([]byte, 32)
	_, err := rand.Read(jwtSecret)
	if err != nil {
		log.Fatalf("Failed to generate random secret: %v", err)
	}
}

func generateToken(username string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, _ := token.SignedString(jwtSecret)
	return tokenString
}

func authenticate(c *gin.Context) {
	tokenString, err := c.Cookie("jwt")
	if err != nil {
		c.HTML(200, "auth.tmpl", nil)
		c.Abort()
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		c.HTML(200, "auth.tmpl", nil)
		c.Abort()
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	username := claims["username"].(string)
	c.Set("username", username)
}

func jwtCheck(c *gin.Context) {
	tokenString, err := c.Cookie("jwt")
	if err != nil {
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false})
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false})
		return
	}

	username, ok := claims["username"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":    true,
		"username": username,
	})
}
