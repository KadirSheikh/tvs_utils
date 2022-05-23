package middleware

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/KadirSheikh/tvs_utils/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

const (
	AuthorizationHeaderKey  = "authorization"
	AuthorizationPayloadKey = "authorization_payload"
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

func AuthMiddleware(s utils.JWT) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		fmt.Println("Inside auth middleware")
		authorizationHeader := ctx.GetHeader(AuthorizationHeaderKey)

		log.Println("Inside auth middleware", authorizationHeader)

		if len(authorizationHeader) == 0 {
			utils.BuildRes(utils.ErrInvalidAuthorizeHeader, "Error", nil, nil, ctx)
			fmt.Println("Error 1 ", utils.ErrInvalidAuthorizeHeader)
			return
		}

		fields := strings.Fields(authorizationHeader)
		log.Println("Fields ", fields)
		if len(fields) < 2 {
			utils.BuildRes(utils.ErrInvalidAuthorizeHeaderFmt, "Error", nil, fmt.Errorf("expected fields not present in header"), ctx)
			fmt.Println("Error 2 ", utils.ErrInvalidAuthorizeHeaderFmt, fields)
			return
		}

		accessToken := fields[1]
		payload, err := s.VerifyToken(accessToken)
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
