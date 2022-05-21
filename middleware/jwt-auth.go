package middleware

import (
	"fmt"
	"log"
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
			utils.BuildRes(utils.ErrInvalidAuthorizeHeader, "Error", nil, nil, c)
			log.Println("Error 1 ", utils.ErrInvalidAuthorizeHeader)
			return
		}
		token, err := jwtService.ValidateToken(authHeader)
		if token.Valid {
			claims := token.Claims.(jwt.MapClaims)
			log.Println("Claim[loginid]: ", claims["loginid"])
		} else {
			log.Println(err)
			utils.BuildRes(utils.ErrInvalidAccessToken, "Error", nil, err, c)
		}
	}
}

func AuthMiddleware(jwtService utils.JWT) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		authorizationHeader := ctx.GetHeader(AuthorizationHeaderKey)

		if len(authorizationHeader) == 0 {
			utils.BuildRes(utils.ErrInvalidAuthorizeHeader, "Error", nil, nil, ctx)

			return
		}

		fields := strings.Fields(authorizationHeader)

		if len(fields) < 2 {
			utils.BuildRes(utils.ErrInvalidAuthorizeHeaderFmt, "Error", nil, fmt.Errorf("expected fields not present in header"), ctx)

			return
		}

		accessToken := fields[1]
		payload, err := jwtService.VerifyToken(accessToken)
		if err != nil {

			utils.BuildRes(utils.ErrInvalidAccessToken, "Error", nil, err, ctx)
			return
		}

		ctx.Writer.Header().Set("Content-Type", "application/json")
		ctx.Set(AuthorizationPayloadKey, payload)
		ctx.Next()
	}
}
