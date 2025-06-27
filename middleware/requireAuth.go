package middleware

import (
	"auth/config"
	"auth/model"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// RequireAuth middleware untuk memverifikasi JWT dari cookie "Authorization"
func RequireAuth(c *gin.Context) {
	// 1. Ambil cookie Authorization dari request
	tokenString, err := c.Cookie("Authorization")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token tidak ditemukan"})
		return
	}

	// 2. Siapkan claims
	claims := &jwt.RegisteredClaims{}

	// 3. Parse dan validasi token
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// 3a. Validasi metode signing harus HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("metode signing tidak valid: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token tidak valid atau expired"})
		return
	}

	// 4. Ambil user ID dari claims.Subject
	userID := claims.Subject
	if userID == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token tidak memiliki subject"})
		return
	}

	// 5. Query user dari database berdasarkan userID
	var user model.User
	if err := config.DB.First(&user, userID).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User tidak ditemukan"})
		return
	}

	// 6. Set userID ke context
	c.Set("userID", userID)

	// 7. Lanjut ke handler berikutnya
	c.Next()
}
