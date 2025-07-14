// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sendmail

import (
	gviper "github.com/spf13/viper"
)

var (
	viper *gviper.Viper
)

func Init(viperIn *gviper.Viper) {
	viper = viperIn
}

type Setting struct {
	Provider           string
	LocalName          string
	From               string
	ServiceAccountFile string
}

func LoadSetting() *Setting {
	return &Setting{
		Provider:           viper.GetString("send_email_config.provider"),
		LocalName:          viper.GetString("send_email_config.local_name"),
		From:               viper.GetString("send_email_config.from_address"),
		ServiceAccountFile: viper.GetString("send_email_config.service_account_file"),
	}
}

func (s *Setting) Valid() bool {
	return s.Provider != "" && s.LocalName != "" &&
		s.From != "" && s.ServiceAccountFile != ""
}
