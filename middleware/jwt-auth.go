package middleware

import (
	"log"
	"net/http"

	"github.com/KadirSheikh/tvs_utils/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func AuthorizeJWT(jwtService utils.JWT) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			res := utils.NotFound(3)
			response := utils.BuildResponse(res.Message, res.Code, nil)
			c.AbortWithStatusJSON(http.StatusNotFound, response)
			return
		}
		token, err := jwtService.ValidateToken(authHeader)
		if token.Valid {
			claims := token.Claims.(jwt.MapClaims)
			log.Println("Claim[userid]: ", claims["userid"])
		} else {
			log.Println(err)
			res := utils.BadRequest()
			response := utils.BuildResponse(res.Message, res.Code, nil)
			c.AbortWithStatusJSON(http.StatusUnauthorized, response)
		}
	}
}
