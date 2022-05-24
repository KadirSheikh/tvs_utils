package middleware

import (
	"fmt"
	"log"
	"net/http"

	"github.com/KadirSheikh/tvs_utils/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

const (
	AuthorizationHeaderKey  = "authorization"
	AuthorizationPayloadKey = "authorization_payload"

	Loginid = "loginid"
	Roleid  = "roleid"
	Userid  = "userid"
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
			c.Set(Loginid, claims["loginid"])
			c.Set(Roleid, claims["roleid"])
			c.Set(Userid, claims["userid"])
			c.Next()
		} else {
			log.Println(err)
			res := utils.BadRequest()
			response := utils.BuildResponse(res.Message, res.Code, nil)
			c.AbortWithStatusJSON(http.StatusUnauthorized, response)
		}
	}
}

func AuthMiddleware(s utils.JWT) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		payload, err := s.VerifyToken(authHeader)
		if err != nil {
			fmt.Println("Verify token error ", err, payload)
			utils.BuildRes(utils.ErrInvalidAccessToken, "Error", nil, err, ctx)
			return
		}

		log.Println("Got payload ", payload)

		ctx.Writer.Header().Set("Content-Type", "application/json")
		ctx.Set(AuthorizationPayloadKey, payload)
		ctx.Next()
	}
}
