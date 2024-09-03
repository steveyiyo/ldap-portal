package webserver

import (
	"log"

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
	router.GET("/", webServer)
	router.GET("/login", loginPage)
	router.NoRoute(pageNotAvailable)

	v1Api := router.Group("v1/api/")
	v1Api.GET("/getuserinfo", authenticate, getLdapUserInfo)
	v1Api.POST("/login", ldapLogin)

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
func webServer(c *gin.Context) {
	c.HTML(200, "index.tmpl", nil)
}

// 404 Page
func pageNotAvailable(c *gin.Context) {
	c.HTML(404, "404.tmpl", nil)
}

// Login Page
func loginPage(c *gin.Context) {
	c.HTML(200, "login.tmpl", nil)
}
