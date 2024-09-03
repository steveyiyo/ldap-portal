package webserver

import (
	"crypto/rand"
	"log"
	"net/http"
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
		// c.JSON(400, gin.H{
		// 	"error": "JWT cookie not found or empty",
		// })
		c.Redirect(302, "/login")
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		c.Abort()
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	username := claims["username"].(string)

	c.Set("username", username)
}
