// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"errors"
	"os"

	"gopkg.in/yaml.v2"
)

type PolicyTargetConfig struct {
	Id       string   `yaml:"id"`
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	FQDNList []string `yaml:"fqdn_list"`
}

type PolicyConfig struct {
	Targets []PolicyTargetConfig `yaml:"targets"`
}

var (
	policyConfig *PolicyConfig
)

func init() {
	policyConfig = nil
}

func GetPolicyConfig() *PolicyConfig {
	return policyConfig
}

func LoadPolicyConfigure(filename string) error {
	if filename == "" {
		return errors.New("invalid filename")
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	Config := PolicyConfig{}
	if err = decoder.Decode(&Config); err != nil {
		return err
	}

	policyConfig = &Config
	return nil
}
