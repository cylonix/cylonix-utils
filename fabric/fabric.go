// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package fabric

import (
	"fmt"
	"reflect"
	"regexp"
	"runtime"
	"sync"

	"github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"
)

type CallbackFn func(interface{}, string, string, ActionType)

var _globalFabricRegisterCbStore map[string]map[string][]CallbackFn = make(map[string]map[string][]CallbackFn)

// Fabric means you can register some instance here for other to use
var fabricCache map[string]map[string]interface{} = make(map[string]map[string]interface{})
var fabricCacheLock sync.RWMutex

// RegisterResource register resources to global
func RegisterResource(typ string, name string, instance interface{}, logger *logrus.Entry) {
	fabricCacheLock.Lock()
	defer fabricCacheLock.Unlock()

	localLogger := logger.WithFields(logrus.Fields{
		log.Handle:    "fabric",
		log.SubHandle: "register-resource",
		"type":        typ,
		"name":        name,
	})

	localLogger.Infoln("Register resource...")

	if _, ok := fabricCache[typ]; !ok {
		fabricCache[typ] = make(map[string]interface{})
	}
	fabricCache[typ][name] = instance
}

// UnRegisterResource register resources to global
func UnRegisterResource(typ, name string, logger *logrus.Entry) {
	fabricCacheLock.Lock()
	defer fabricCacheLock.Unlock()

	localLogger := logger.WithFields(logrus.Fields{
		log.Handle:    "fabric",
		log.SubHandle: "unregister-resource",
		"type":        typ,
		"name":        name,
	})

	localLogger.Infoln("UnRegister resource...")

	if _, ok := fabricCache[typ]; !ok {
		localLogger.WithField("type", typ).Warnln("UnRegister resource type not exist")
		return
	}
	delete(fabricCache[typ], name)
	if len(fabricCache[typ]) == 0 {
		delete(fabricCache, typ)
	}
}

func Fire(typ, name string, action ActionType, logger *logrus.Entry) {
	_logger := logger.WithFields(logrus.Fields{
		log.Handle:    "fabric",
		log.SubHandle: "fire",
		"type":        typ,
		"name":        name,
		"action":      action,
	})
	_logger.Infoln("Fire...")
	instance, err := GetResource(typ, name)
	if err != nil {
		_logger.WithError(err).Warnln("Resource is not registered")
		return
	}

	// Do we need to inform the ones which interested to this resource?
	// We should use the regex to for some purpose
	if _, ok := _globalFabricRegisterCbStore[typ]; !ok {
		_logger.Infoln("No this type callback is registered, skip it.")
		return
	}
	_logger.Debugln("invoke callback")
	for k := range _globalFabricRegisterCbStore[typ] {
		_logger.Debugln("checking ", k, name)
		matched, err := regexp.Match(k, []byte(name));
		if err != nil {
			_logger.WithError(err).Warnln("match error")
			continue
		}

		if matched {
			if cbs, ok := _globalFabricRegisterCbStore[typ][k]; ok {
				for _, cb := range cbs {
					_logger.
						WithFields(logrus.Fields{"match": k, "real": name}).
						Debugln("Found callback, call it")
					cb(instance, typ, name, action)
				}
			}
		}
	}
}

func RegisterCallback(typ, name string, cb CallbackFn, logger *logrus.Entry) {
	logger.WithFields(logrus.Fields{
		log.Handle:    "fabric",
		log.SubHandle: "register callback",
		"type":        typ,
		"name":        name,
		"callback":    runtime.FuncForPC(reflect.ValueOf(cb).Pointer()).Name(),
	}).Infoln("Register callback...")

	if _, ok := _globalFabricRegisterCbStore[typ]; !ok {
		_globalFabricRegisterCbStore[typ] = make(map[string][]CallbackFn)
	}

	_globalFabricRegisterCbStore[typ][name] = append(_globalFabricRegisterCbStore[typ][name], cb)
}

func GetResource(typ string, name string) (interface{}, error) {
	fabricCacheLock.RLock()
	defer fabricCacheLock.RUnlock()

	// Type first
	if _, ok := fabricCache[typ]; !ok {
		return nil, fmt.Errorf("cannot get resource type %v", typ)
	}

	if rt, ok := fabricCache[typ][name]; ok {
		return rt, nil
	} else {
		return nil, fmt.Errorf("cannot get resource %v, with type %v", name, typ)
	}
}
