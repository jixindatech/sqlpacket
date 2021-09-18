package config

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

var configFileName string

//整个config文件对应的结构
type Config struct {
	Addr string `yaml:"addr"`
	Dev  string `yaml:"dev"`
}

func ParseConfigData(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func ParseConfigFile(fileName string) (*Config, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	configFileName = fileName

	return ParseConfigData(data)
}
