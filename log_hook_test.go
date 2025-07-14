// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestLogFilterConfig(t *testing.T) {
	Init(nil)
	viper.SetConfigType("yaml")
	testNamespace1, testNamespace2 := "test-namespace1", "test-namespace2"
	config := []byte(fmt.Sprintf(`
%v:
  match_all: true
  log_levels:
    - debug
    - info
    - warn
  filters:
    key: %v
    contain:
      - %v
      - %v
`, logFilterConfigName, ulog.Namespace, testNamespace1, testNamespace2))
	err := viper.ReadConfig(bytes.NewBuffer(config))
	if !assert.Nil(t, err) {
		return
	}
	cfg := &LogFilterConfig{}
	err = viper.UnmarshalKey(logFilterConfigName, cfg)
	if !assert.Nil(t, err) {
		return
	}
	cfg, err = setLogFilterConfig(cfg)
	if !assert.Nil(t, err) {
		return
	}

	// Check all configs are set correctly.
	assert.True(t, cfg.MatchAll)
	assert.Equal(t, 3, len(cfg.LogLevels))
	assert.Equal(t, 3, len(cfg.levels))
	if (assert.Equal(t, 1, len(cfg.Filters))) {
		assert.Equal(t, 2, len(cfg.Filters[0].Contain))
	}

	logger := logrus.New()
	output := logger.Out
	defer func() {
		logger.Out = output
	}()

	// Debug level log without any filter matching. Expect output discard.
	entry := logrus.NewEntry(logger)
	entry.Level = logrus.DebugLevel
	err = cfg.Fire(entry)
	assert.Nil(t, err)
	assert.Equal(t, io.Discard, logger.Out)

	// Debug level log with filter matching. Expect output restored.
	entry = entry.WithField(ulog.Namespace, testNamespace1)
	entry.Level=logrus.DebugLevel
	err = cfg.Fire(entry)
	assert.Nil(t, err)
	assert.NotEqual(t, io.Discard, logger.Out)

	// Set output to discard and expect panic log restores output..
	cfg.setDiscard(logger)
	assert.Equal(t, io.Discard, logger.Out)
	entry = logrus.NewEntry(logger)
	entry.Level = logrus.PanicLevel
	err = cfg.Fire(entry)
	assert.Nil(t, err)
	assert.NotEqual(t, io.Discard, logger.Out)

	// Test hooks firing.
	logger.SetLevel(logrus.DebugLevel)
	logger.AddHook(cfg)

	// Debug log triggers output discard.
	logger.Debugln("test debug discard")
	assert.Equal(t, io.Discard, logger.Out)

	// Debug log with filter matched enables output.
	logger.WithField(ulog.Namespace, testNamespace2).Debugln("test debug namespace2 restores output.")
	assert.NotEqual(t, io.Discard, logger.Out)

	// Set output to discard and expect error log restores output.
	cfg.setDiscard(logger)
	assert.Equal(t, io.Discard, logger.Out)
	logger.Errorln("test error restore output")
	assert.NotEqual(t, io.Discard, logger.Out)
}
