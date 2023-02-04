package config

import (
	"gopkg.in/yaml.v2"
	"os"
)

// Config 整个config文件对应的结构
type Config struct {
	Server string `yaml:"server"`
	Inf    string `yaml:"inf"`
	Type   string `yaml:"type"`
	Port   uint16 `yaml:"port"`
}

func ParseConfigData(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func ParseConfigFile(fileName string) (*Config, error) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	return ParseConfigData(data)
}
