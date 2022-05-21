package utils

import (
	"fmt"
	"sync"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Database database             `toml:"database"`
	Server   server               `toml:"server"`
	Comm     servicecommunication `toml:"servicecommunication"`
	AuthInfo authkey              `toml:"authkey"`
}

type database struct {
	Host     string
	Database string
	User     string
	Password string
}

type server struct {
	Port string
}

type servicecommunication struct {
	Port string
}

type authkey struct {
	Secretkey string
}

var conf *Config
var lock = &sync.Mutex{}

func NewConfig() *Config {
	if conf == nil {
		lock.Lock()
		defer lock.Unlock()

		if conf == nil {
			if _, err := toml.DecodeFile("./config.toml", &conf); err != nil {

				panic("Could not able to read configuration")
			}

			fmt.Printf("%#v\n", conf)
			return conf
		} else {
			return conf
		}
	}

	return conf
}

// func NewConfig() *Config {
// 	var conf Config
// 	if _, err := toml.DecodeFile("./config.toml", &conf); err != nil {
// 		fmt.Println(err)
// 	}

// 	return &conf
// }
