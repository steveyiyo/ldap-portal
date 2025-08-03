package webserver

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/steveyiyo/ldap-portal/internal/auth"
)

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

func listUsersHandler(c *gin.Context) {
	users, err := auth.LdapListUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "users": users})
}

func getUserDetailsHandler(c *gin.Context) {
	username := c.Param("username")
	details, err := auth.LdapGetUserDetails(username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "user": details})
}
