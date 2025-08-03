package webserver

import (
	"log"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/steveyiyo/ldap-portal/internal/auth"
)

func Init(listen string) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	router.Use(cors.New(config))
	router.LoadHTMLGlob("data/static/*")
	router.GET("/", authenticate, indexPage)
	router.GET("/login", loginPage)
	router.GET("/logout", authLogout)
	router.GET("/register", registerPage)
	router.GET("/reset-password", authenticate, resetPwdPage)
	// router.GET("/forgot-password", authenticate, resetPwdPage)

	router.NoRoute(pageNotAvailable)

	v1Api := router.Group("/api/v1")
	v1Api.GET("/getuserinfo", authenticate, getLdapUserInfo)
	v1Api.POST("/login", ldapLogin)
	v1Api.POST("/reset-password", authenticate, ldapResetPassword)
	v1Api.POST("/register", ldapCreateUser)

	// Debug
	router.GET("/check-jwt", func(c *gin.Context) {
		headers := c.Request.Header
		c.JSON(200, gin.H{
			"headers": headers,
		})
	})

	log.Printf("Server run on the %s", listen)
	router.Run(listen)
}

// Index Page
func indexPage(c *gin.Context) {
	// c.HTML(200, "index.tmpl", nil)

	// If user is not authorized
	// c.Redirect(302, "/login")

	// If user is authorized

	// Get Username
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

	c.JSON(200, gin.H{
		"message":  "Welcome to LDAP Portal",
		"Username": username,
		"Name":     userInfo["cn"],
		"Email":    userInfo["mail"],
		"MemberOf": userInfo["memberOf"],
	})
}

// 404 Page
func pageNotAvailable(c *gin.Context) {
	c.HTML(404, "404.tmpl", nil)
}

// Login Page
func loginPage(c *gin.Context) {
	// Check if User Login

	_, err := c.Cookie("jwt")

	if err != nil {
		// c.JSON(400, gin.H{
		// 	"error": "JWT cookie not found or empty",
		// })
		c.HTML(200, "login.tmpl", nil)
		return
	}

	c.Redirect(302, "/")
}

// Login Page
func registerPage(c *gin.Context) {
	// Check if User Login

	_, err := c.Cookie("jwt")

	if err != nil {
		c.HTML(200, "register.tmpl", nil)
		return
	}

	c.Redirect(302, "/")
}

// Reset Password Page
func resetPwdPage(c *gin.Context) {
	c.HTML(200, "resetpwd.tmpl", nil)
}
