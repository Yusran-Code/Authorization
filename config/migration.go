package config

import "auth/model"

func MigrationDb()  {
	DB.AutoMigrate(&model.User{})
}