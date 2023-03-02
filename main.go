package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var signingKey = []byte("secret-key")

const tokenExpiration = time.Hour * 24

func generateToken(userId int64) (string, error) {
	claims := jwt.MapClaims{
		"userId": userId,
		"exp":    time.Now().Add(tokenExpiration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func validateToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		fmt.Println(authHeader)
		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return signingKey, nil
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			userId := claims["userId"].(float64)
			c.Set("userId", int64(userId))
			c.Next() // ini keyword untuk menlanjutkan ke middleware selanjutnya, atau ke endpointnya
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
	}
}

func main() {
	r := gin.Default()

	r.POST("/login", func(c *gin.Context) {
		var userId int64 = 123
		token, _ := generateToken(userId)
		c.JSON(http.StatusOK, gin.H{"token": token})
	})

	r.GET("/profile", validateToken(), func(c *gin.Context) {
		userId := c.GetInt64("userId")
		c.JSON(http.StatusOK, gin.H{"userId": userId, "msg": "yeay login berhasil"})
	})

	r.Run(":8080")
}
