package utils

import (
	"fmt"
	"sync"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Database database
	Server   server
}

type database struct {
	Host     string
	Database string
	User     string
	Password string
	Secret   string
}

type server struct {
	Port string
}

var conf *Config
var lock = &sync.Mutex{}

func NewConfig() *Config {
	if conf == nil {
		lock.Lock()
		defer lock.Unlock()

		if conf == nil {

			if _, err := toml.DecodeFile("./config.toml", &conf); err != nil {
				fmt.Println(err)
			}

			fmt.Printf("%#v\n", conf)

			return conf
		} else {
			return conf
		}
	}

	return conf
}
