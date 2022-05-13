package utils

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type JWT interface {
	GenerateToken(Userid uint64, Loginid string, Roleid uint64) string
	ValidateToken(token string) (*jwt.Token, error)
}

type jwtCustomClaim struct {
	Userid  uint64 `json:"userid"`
	Loginid string `json:"loginid"`
	Roleid  uint64 `json:"roleid"`
	jwt.StandardClaims
}

type jwtToken struct {
	secretKey string
	issuer    string
}

func NewJWTService() JWT {
	return &jwtToken{
		issuer:    "trafficviolationsystem",
		secretKey: getSecretKey(),
	}
}

func getSecretKey() string {
	conf := NewConfig()
	secretKey := conf.Database.Secret

	if secretKey != "" {
		secretKey = "trafficviolationsystemjwt"
	}
	return secretKey
}

func (j *jwtToken) GenerateToken(Userid uint64, Loginid string, Roleid uint64) string {

	claims := &jwtCustomClaim{
		Userid,
		Loginid,
		Roleid,
		jwt.StandardClaims{
			ExpiresAt: time.Now().AddDate(1, 0, 0).Unix(),
			Issuer:    j.issuer,
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(j.secretKey))
	if err != nil {
		panic(err)
	}
	return t
}

func (j *jwtToken) ValidateToken(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t_ *jwt.Token) (interface{}, error) {
		if _, ok := t_.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t_.Header["alg"])
		}
		return []byte(j.secretKey), nil
	})
}
