package utils

import gviper "github.com/spf13/viper"

var (
	viper *gviper.Viper
)

func Init(viperIn *gviper.Viper) {
	if viperIn == nil {
		viper = gviper.GetViper()
	} else {
		viper = viperIn
	}
}
