package utils

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type JWT interface {
	GenerateServiceValidationToken(chasisno, vehicleregno string) string
	GenerateToken(Userid uint64, Loginid string, Roleid uint64) string
	ValidateToken(token string) (*jwt.Token, error)
	VerifyToken(token string) (*Payload, error)
}

type jwtCustomClaim struct {
	Userid  uint64 `json:"userid"`
	Loginid string `json:"loginid"`
	Roleid  uint64 `json:"roleid"`
	jwt.StandardClaims
}

type Payload struct {
	ChasisNumber string `json:"chasisno"`
	Vehicleregno string `json:"vehicleregno"`
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
			ExpiresAt: time.Now().Add(time.Minute * 45).Unix(),
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

func (j *jwtToken) GenerateServiceValidationToken(chasisno, vehicleregno string) string {

	claims := &Payload{
		chasisno,
		vehicleregno,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * 45).Unix(),
			Issuer:    j.issuer,
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	t, err := token.SignedString([]byte(j.secretKey))

	if err != nil {
		panic(err)
	}
	log.Print(t)
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

func (j *jwtToken) VerifyToken(token string) (*Payload, error) {
	jwtToken, err := jwt.ParseWithClaims(token, &Payload{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			fmt.Println("Algo used ", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method %s", token.Header["alg"])
		}

		str, _ := base64.StdEncoding.DecodeString(j.secretKey)
		return str, nil
	})

	fmt.Println("verify Error : ", err, err.(*jwt.ValidationError))

	payload, ok := jwtToken.Claims.(*Payload)
	if !ok {
		return nil, errors.New("token is invalid, could not parse claims")
	}

	if payload.ExpiresAt < time.Now().Local().Unix() {
		return nil, errors.New("token is expired")
	}

	return payload, nil
}
