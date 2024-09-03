package webserver

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/steveyiyo/ldap-portal/internal/auth"
)

func ldapLogin(c *gin.Context) {
	loginUser := c.PostForm("username")
	loginPwd := c.PostForm("password")
	loginCheck, loginMessage := auth.LdapAuthUser(loginUser, loginPwd)
	if loginCheck {
		// Authentication successful, generate JWT
		tokenString := generateToken(loginUser)

		// Set a cookie with the JWT and return it to the client
		c.SetCookie(
			"jwt",       // Cookie name
			tokenString, // Cookie value (JWT token)
			3600,        // Expiration time in seconds
			"/",         // Path
			"localhost", // Domain
			false,       // Secure flag (true = HTTPS only)
			true,        // HttpOnly (true = HTTP access only, no JavaScript)
		)

		// c.String(200, fmt.Sprintf("User %s is authorized.", loginUser))
		c.Redirect(302, "/v1/api/getuserinfo")
	} else {
		c.String(401, fmt.Sprintf("User %s not authorized. Error message: %s", loginUser, loginMessage))
	}
}

func getLdapUserInfo(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Call LdapGetUserInfo function to retrieve user information
	userInfo, err := auth.LdapGetUserInfo(username.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user info"})
		return
	}

	c.JSON(200, userInfo)
}
