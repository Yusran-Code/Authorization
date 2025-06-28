package controllers

import (
	"auth/config"
	"auth/model"
	"strconv"

	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func Daftar(c *gin.Context) {
	var data model.User

	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// hash
	hash, err := bcrypt.GenerateFromPassword([]byte(data.Password), 10)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"error": "error data hash"})
		return
	}

	// create user
	user := model.User{Email: data.Email, Password: string(hash)}

	if err := config.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed create"})
		return
	}

	// respon
	c.JSON(200, gin.H{"email": data.Email})
}

func Login(c *gin.Context) {
	//get email/decode
	var data model.User

	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	//look up request user
	var user model.User
	if err := config.DB.First(&user, "email = ?", data.Email).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email or password"})
		return
	}

	//compare sent and saved has
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(data.Password)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email or password"})
		return
	}
	//generate jwt
	claims := jwt.RegisteredClaims{
		Subject:   strconv.Itoa(int(user.ID)),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed create token"})
		return
	}

	//send back
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"message": "Login success",
		"token":   tokenString,
		"email":   user.Email,
	})
}

func Validasi(c *gin.Context) {
	userID, _ := c.Get("userID")
	c.JSON(200, gin.H{"message": userID})
}
func Logout(c *gin.Context) {
	c.SetCookie("Authorization", "", -1, "", "", false, true)
	c.JSON(200, gin.H{"message": "Logout sukses"})
}
