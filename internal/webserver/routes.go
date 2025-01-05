package webserver

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"

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
			"jwt",          // Cookie name
			tokenString,    // Cookie value (JWT token)
			3600,           // Expiration time in seconds
			"/",            // Path
			c.Request.Host, // Domain
			false,          // Secure flag (true = HTTPS only)
			true,           // HttpOnly (true = HTTP access only, no JavaScript)
		)

		// c.String(200, fmt.Sprintf("User %s is authorized.", loginUser))
		// c.Redirect(302, "/v1/api/getuserinfo")

		// Redirect to the Index Page
		c.Redirect(302, "/")
	} else {
		c.String(401, fmt.Sprintf("User %s not authorized. Error message: %s", loginUser, loginMessage))
	}
}

// Generate Hash Password
func hashPwd(password string) string {
	b := make([]byte, 4)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		fmt.Println("無法生成雜湊")
		os.Exit(1)
	}
	h := sha1.New()
	h.Write([]byte(password))
	h.Write(b)
	sum := h.Sum(nil)
	r := append(sum, b...)
	return fmt.Sprintf("{SSHA}%s", base64.StdEncoding.EncodeToString(r))
}

// Create User
func ldapCreateUser(c *gin.Context) {
	var user auth.UserProfile
	user.Email = c.PostForm("email")
	user.FirstName = c.PostForm("first_name")
	user.LastName = c.PostForm("last_name")
	user.Uid = c.PostForm("username")
	user.HashPassword = hashPwd(c.PostForm("password"))

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "參數錯誤"})
		return
	}
	auth.LeapCreateUser(user)
	c.JSON(http.StatusOK, gin.H{"status": "使用者已建立"})
}

func authLogout(c *gin.Context) {
	c.SetCookie(
		"jwt",
		"",
		-1,
		"/",
		c.Request.Host,
		false,
		true,
	)
	c.Redirect(302, "/login")
}

func ldapResetPassword(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	oldPwd := c.PostForm("oldPassword")
	newPwd := c.PostForm("newPassword")

	err := auth.LdapChangePassword(username.(string), oldPwd, newPwd)
	if err != nil {
		c.String(500, "Password update failed, reason: %s", err)
		return
	}

	c.String(200, "Username %s Password updated!", username)
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
