package main

import (
	"auth/config"
	"auth/controllers"
	"auth/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	config.LoadEnv()
	config.InitDatabase()
	config.MigrationDb()
}

func main() {
	router := gin.Default()
	router.POST("/daftar", controllers.Daftar)
	router.POST("/login", controllers.Login)
	router.GET("/validasi", middleware.RequireAuth, controllers.Validasi)
	router.Run()
}
