package utils

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

var (
	ErrInvalidRedirectURI        = errors.New("invalid redirect uri")
	ErrInvalidAuthorizeHeader    = errors.New("missing/invalid authorization header")
	ErrInvalidAuthorizeHeaderFmt = errors.New("invalid authorization header format")
	ErrInvalidAuthorizeCode      = errors.New("invalid authorize code")
	ErrInvalidAccessToken        = errors.New("invalid access token")
	ErrInvalidRefreshToken       = errors.New("invalid refresh token")
	ErrExpiredAccessToken        = errors.New("expired access token")
	ErrExpiredRefreshToken       = errors.New("expired refresh token")
	ErrInvalidRequestParam       = errors.New("invalid request param")
	ErrFailToDecodeTomlFile      = errors.New("failed to decode toml file")
	ErrConflict                  = errors.New("record already exists")
	ErrRecordNotFound            = errors.New("record not found")
	ErrInvalidSyntax             = errors.New("invalid syntax")
)

var StatusCodes = map[error]int{
	ErrInvalidRedirectURI:        400,
	ErrInvalidAuthorizeHeader:    401,
	ErrInvalidAuthorizeHeaderFmt: 401,
	ErrInvalidAuthorizeCode:      401,
	ErrInvalidAccessToken:        401,
	ErrInvalidRefreshToken:       401,
	ErrExpiredAccessToken:        401,
	ErrExpiredRefreshToken:       401,
	ErrInvalidRequestParam:       400,
	ErrConflict:                  409,
	ErrRecordNotFound:            404,
	ErrInvalidSyntax:             400,
}

func BuildRes(err error, title string, data interface{}, message error, c *gin.Context) {
	if err != nil {
		if _, ok := StatusCodes[err]; ok {
			if err == message {
				c.AbortWithStatusJSON(StatusCodes[err],
					gin.H{
						"error": err.Error(),
					})
			} else {
				c.AbortWithStatusJSON(StatusCodes[err],
					gin.H{
						"error":   err.Error(),
						"message": message.Error(),
					})
			}
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				title:     err.Error(),
				"Details": message.Error(),
			})
		}
		return
	}

	fmt.Println("Object ", data)
	c.JSON(http.StatusOK, gin.H{title: data})
}
