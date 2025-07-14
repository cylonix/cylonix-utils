// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"reflect"
	"slices"
	"strings"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/sirupsen/logrus"
)

var (
	logFilterConfigName = "log_filter_config"
	logFilterConfig     *LogFilterConfig
)

type Filter struct {
	Key     string   `mapstructure:"key"`
	Contain []string `mapstructure:"contain"`
}

type LogFilterConfig struct {
	LogLevels []string `mapstructure:"log_levels"`
	Filters   []Filter `mapstructure:"filters"`   // Key values to match
	MatchAll  bool     `mapstructure:"match_all"` // If to match all filters

	levels        []logrus.Level
	zeroLogLevels []zerolog.Level
	savedOutput   io.Writer
}

func (f *LogFilterConfig) IsEmpty() bool {
	return len(f.LogLevels) <= 0 || len(f.Filters) <= 0
}

// GetLogFilterConfig returns no error if there is no config set.
func GetLogFilterConfig() (*LogFilterConfig, error) {
	if logFilterConfig != nil {
		return logFilterConfig, nil
	}
	cfg := &LogFilterConfig{}
	err := viper.UnmarshalKey(logFilterConfigName, cfg)
	if err != nil {
		return nil, err
	}
	if cfg.IsEmpty() {
		s, _ := json.Marshal(cfg)
		log.Printf("Empty log filter configs: %v", string(s))
		return nil, nil
	}
	return setLogFilterConfig(cfg)
}
func setLogFilterConfig(cfg *LogFilterConfig) (*LogFilterConfig, error) {
	s, _ := json.Marshal(cfg)
	log.Printf("log filter configs: %v", string(s))
	var levels []logrus.Level
	for _, levelString := range cfg.LogLevels {
		level, err := logrus.ParseLevel(levelString)
		if err != nil {
			return nil, err
		}
		levels = append(levels, level)
		zeroLogLevel, err := zerolog.ParseLevel(levelString)
		if err != nil {
			return nil, err
		}
		cfg.zeroLogLevels = append(cfg.zeroLogLevels, zeroLogLevel)
	}
	if len(levels) <= 0 {
		levels = append(levels, logrus.DebugLevel)
	}
	slices.Sort(levels)
	cfg.levels = levels
	logFilterConfig = cfg
	SetGlobalZeroLogHookWithConfig(cfg)
	return cfg, nil
}

func (c *LogFilterConfig) LogLevel() logrus.Level {
	return c.levels[len(c.levels)-1]
}

func (c *LogFilterConfig) Levels() []logrus.Level {
	// Include all levels so that we can restore output if not to be filtered.
	return logrus.AllLevels
}

func (c *LogFilterConfig) restoreOutput(logger *logrus.Logger) {
	if c.savedOutput != nil && logger.Out == io.Discard {
		logger.Out = c.savedOutput
	}
}
func (c *LogFilterConfig) setDiscard(logger *logrus.Logger) {
	if logger.Out != io.Discard {
		c.savedOutput = logger.Out
	}
	logger.Out = io.Discard
}

func (c *LogFilterConfig) match(fields map[string]interface{}, message string) int {
	matched := 0
	for _, f := range c.Filters {
		matchedFilter := false

		var value *string
		if f.Key == "" {
			// Empty key value means message body.
			value = &message
		} else if fields != nil {
			if fields[f.Key] != nil {
				if s, ok := fields[f.Key].(string); ok {
					value = &s
				}
			}
		}
		if value != nil {
			for _, s := range f.Contain {
				if strings.Contains(*value, s) {
					matchedFilter = true
					break
				}
			}
		}

		if matchedFilter {
			matched += 1
			if !c.MatchAll {
				break
			}
		} else {
			if c.MatchAll {
				break
			}
		}
	}
	return matched
}

func (c *LogFilterConfig) Fire(entry *logrus.Entry) error {
	level := entry.Level
	fields := entry.Data

	if len(c.Filters) <= 0 ||
		level <= logrus.PanicLevel ||
		!slices.Contains(c.levels, level) {
		c.restoreOutput(entry.Logger)
		return nil
	}

	matched := c.match(fields, entry.Message)
	if matched <= 0 || (c.MatchAll && matched != len(c.Filters)) {
		c.setDiscard(entry.Logger)
	} else {
		c.restoreOutput(entry.Logger)
	}
	return nil
}

func (c *LogFilterConfig) Run(e *zerolog.Event, level zerolog.Level, message string) {
	if len(c.Filters) <= 0 ||
		!slices.Contains(c.zeroLogLevels, level) {
		return
	}

	fields, _, err := ZeroLogFields(e, message)
	if err != nil {
		return
	}

	matched := c.match(fields, message)
	if matched <= 0 || (c.MatchAll && matched != len(c.Filters)) {
		e.Discard()
	}
}

type ErrorLogHook struct {
	Handler func(entry *logrus.Entry) error
}

func (h *ErrorLogHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.ErrorLevel,
	}
}

func (h *ErrorLogHook) Fire(entry *logrus.Entry) error {
	if h.Handler != nil {
		return h.Handler(entry)
	}
	return nil
}

type ZeroLogHook struct {
	hooks map[zerolog.Level]zerolog.HookFunc
}

// Until the following feature is supported.
// https://github.com/rs/zerolog/issues/493
// https://github.com/rs/zerolog/pull/682
func ZeroLogFields(e *zerolog.Event, message string) (map[string]interface{}, string, error) {
	logData := make(map[string]interface{})
	ev := fmt.Sprintf("%s, \"message\": \"%v\"}", reflect.ValueOf(e).Elem().FieldByName("buf"), message)
	if err := json.Unmarshal([]byte(ev), &logData); err != nil {
		return nil, "", err
	}
	return logData, ev, nil
}

var zeroLogHook = &ZeroLogHook{hooks: make(map[zerolog.Level]zerolog.HookFunc)}

// ZeorLogHook implements the zerolog Hook interface.
func (h *ZeroLogHook) Run(e *zerolog.Event, level zerolog.Level, message string) {
	hook, ok := h.hooks[level]
	if !ok || hook == nil {
		return
	}
	hook(e, level, message)
}

func SetGlobalZeroLogHook(level zerolog.Level, hook zerolog.HookFunc) {
	log.Printf("setting hook for level %v\n", level)
	zeroLogHook.hooks[level] = hook
}

func SetGlobalZeroLogHookWithConfig(c *LogFilterConfig) {
	for _, l := range c.zeroLogLevels {
		SetGlobalZeroLogHook(l, c.Run)
	}
}

func init() {
	zlog.Logger = zlog.Hook(zeroLogHook)
}