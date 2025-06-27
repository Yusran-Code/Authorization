# 🔐 Authorization API with Go (Gin, GORM, PostgreSQL, JWT)

Sistem autentikasi backend menggunakan Golang dengan Gin framework, GORM ORM, PostgreSQL database, dan JWT yang disimpan dalam cookie `Authorization`.

---

## 📦 Dependencies

- Go 1.21+
- Gin Gonic (`github.com/gin-gonic/gin`)
- GORM (`gorm.io/gorm`, `gorm.io/driver/postgres`)
- PostgreSQL
- JWT (`github.com/golang-jwt/jwt/v5`)
- godotenv (`github.com/joho/godotenv`), opsional jika pakai `.env`
- - Bcrypt (`golang.org/x/crypto/bcrypt`)

Install dependencies:
```bash
go mod tidy
