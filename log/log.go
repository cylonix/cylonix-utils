// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package log

import (
	"github.com/sirupsen/logrus"
)

type Fields struct {
	Namespace string
	Username  string
	UserID    string
	MKey      string
	DeviceID  string
	SubHandle string
	m         map[string]interface{}
}

func (f *Fields) set(field, value string) {
	if value != "" {
		f.m[field] = value
	}
}

// Don't use reflector to set the fileds automatically due to its slowness.
func (f *Fields) LogrusFields() logrus.Fields {
	f.m = make(map[string]interface{})
	f.m[Namespace] = f.Namespace // must have
	f.set(Username, f.Username)
	f.set(UserID, f.UserID)
	f.set(DeviceID, f.DeviceID)
	f.set(MKey, f.MKey)
	f.set(SubHandle, f.SubHandle)
	return logrus.Fields(f.m)
}
