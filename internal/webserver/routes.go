package webserver

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/steveyiyo/ldap-portal/internal/auth"
)

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func ldapLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"status": "error", "message": "invalid request"})
		return
	}
	ok, msg := auth.LdapAuthUser(req.Username, req.Password)
	if !ok {
		c.JSON(401, gin.H{"status": "error", "message": msg})
		return
	}
	token := generateToken(req.Username)
	c.SetCookie("jwt", token, 3600, "/", c.Request.Host, false, true)
	c.JSON(200, gin.H{"status": "success", "token": token})
}

// Generate Hash Password
func hashPwd(password string) string {
	b := make([]byte, 4)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		log.Println("無法生成雜湊")
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
	var req struct {
		Email     string `json:"email" binding:"required,email"`
		FirstName string `json:"first_name" binding:"required"`
		LastName  string `json:"last_name" binding:"required"`
		Username  string `json:"username" binding:"required"`
		Password  string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "參數錯誤"})
		return
	}

	user := auth.UserProfile{
		Email:        req.Email,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Uid:          req.Username,
		HashPassword: hashPwd(req.Password),
	}

	if err := auth.LeapCreateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "建立使用者失敗"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "使用者已建立"})
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
	var req struct {
		OldPassword string `json:"oldPassword" binding:"required"`
		NewPassword string `json:"newPassword" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "參數錯誤"})
		return
	}

	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "未授權"})
		return
	}

	if err := auth.LdapChangePassword(username.(string), req.OldPassword, req.NewPassword); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": fmt.Sprintf("密碼更新失敗：%s", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": fmt.Sprintf("使用者 %s 密碼已更新", username)})
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

func getUserInfo(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	info, err := auth.LdapGetUserInfo(username.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user info"})
		return
	}

	response := gin.H{
		"username":          username,
		"displayName":       info["cn"],
		"distinguishedName": info["dn"],
		"email":             info["mail"],
		"groups":            info["memberOf"],
		"lastLogin":         "",
		"createdAt":         "",
		"mfaEnabled":        "",
		"passwordExpiry":    "",
		"status":            "OK",
	}

	c.JSON(http.StatusOK, response)
}

func createServiceAccount(c *gin.Context) {
	var req struct {
		ServiceUsername string `json:"service_username" binding:"required"`
		Password        string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "參數錯誤"})
		return
	}

	svcDn := fmt.Sprintf("cn=%s,ou=ServiceAccounts,dc=steveyi,dc=net", req.ServiceUsername)

	if err := auth.CreateServiceAccount(svcDn, req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Service account 建立完成"})
}
