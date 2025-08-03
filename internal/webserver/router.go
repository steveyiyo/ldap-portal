package webserver

import (
	"log"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func Init(listen string) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	router.Use(cors.New(config))
	router.LoadHTMLGlob("data/static/*")
	router.GET("/", indexPage)
	router.GET("/login", loginPage)
	router.GET("/register", registerPage)
	router.GET("/no-auth", noAuthPage)
	router.GET("/reset-password", authenticate, resetPwdPage)
	// router.GET("/forgot-password", authenticate, resetPwdPage)

	adminRouter := router.Group("/admin")
	{
		adminRouter.GET("/", adminPage)
		adminRouter.GET("/users", adminUserManagementPage)
	}

	router.NoRoute(pageNotAvailable)

	v1Api := router.Group("/api/v1")
	{
		v1Api.GET("/jwt-check", jwtCheck)
		v1Api.POST("/login", ldapLogin)
		v1Api.POST("/logout", authLogout)
		v1Api.POST("/reset-password", authenticate, ldapResetPassword)
		v1Api.POST("/register", ldapCreateUser)
		userInfoApi := v1Api.Group("/getuserinfo")
		{
			userInfoApi.GET("/", authenticate, getUserInfo)
			userInfoApi.GET("/ldap", authenticate, getLdapUserInfo)
		}
		adminApi := v1Api.Group("/admin")
		{
			adminApi.POST("/create/svc", createServiceAccount)
			adminApi.GET("/users", listUsersHandler)
			adminApi.GET("/users/:username", getUserDetailsHandler)
		}
	}

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
	c.HTML(200, "index.tmpl", nil)
}

// 404 Page
func pageNotAvailable(c *gin.Context) {
	c.HTML(404, "404.tmpl", nil)
}

// Login Page
func loginPage(c *gin.Context) {
	tokenString, err := c.Cookie("jwt")
	if err == nil {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err == nil && token.Valid {
			c.Redirect(http.StatusFound, "/")
			return
		}
	}
	c.HTML(http.StatusOK, "login.tmpl", nil)
}

// Login Page
func registerPage(c *gin.Context) {
	// Check if User Login
	tokenString, err := c.Cookie("jwt")
	if err == nil {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err == nil && token.Valid {
			c.Redirect(http.StatusFound, "/")
			return
		}
	}
	c.HTML(http.StatusOK, "register.tmpl", nil)
}

// Reset Password Page
func resetPwdPage(c *gin.Context) {
	c.HTML(200, "resetpwd.tmpl", nil)
}

// Admin Page
func adminPage(c *gin.Context) {
	// Check if User Login
	tokenString, err := c.Cookie("jwt")
	if err == nil {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err == nil && token.Valid {
			c.HTML(http.StatusOK, "admin.tmpl", nil)
			return
		}
	}
	c.Redirect(http.StatusFound, "/")
}

// adminUserManagementPage
func adminUserManagementPage(c *gin.Context) {
	// Check if User Login
	tokenString, err := c.Cookie("jwt")
	if err == nil {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err == nil && token.Valid {
			c.HTML(http.StatusOK, "admin_user_management.tmpl", nil)
			return
		}
	}
	c.Redirect(http.StatusFound, "/")
}

func noAuthPage(c *gin.Context) {
	c.HTML(401, "auth.tmpl", nil)
}
