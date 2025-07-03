package redis

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	rr "github.com/go-redis/redis"
)

type emulator struct {
	kvMap  map[string]string
	hKvMap map[string]map[string]interface{}
	mu     sync.Mutex // use to protect kvMap
}

type emulatorScanCmd struct {
	cursor uint64
	keys   []string
	err    error
}

func (s *emulatorScanCmd) Result() ([]string, uint64, error) {
	return s.keys, s.cursor, s.err
}

func errNotImplemented(method string) error {
	return fmt.Errorf("method %v not implemented", method)
}

func NewEmulator() (ClientInterface, error) {
	return &emulator{
		kvMap:  make(map[string]string),
		hKvMap: make(map[string]map[string]interface{}),
	}, nil
}

func (re *emulator) LRem(key string, count int64, value string) error {
	return re.delete(key)
}

func (re *emulator) Del(key string) error {
	return re.delete(key)
}

func (re *emulator) Get(key string) (string, error) {
	return re.get(key)
}
func (re *emulator) SetWithExpiration(key, value string, expiration time.Duration) error {
	return re.putWithExpiration(key, value, expiration)
}
func (re *emulator) Set(key, value string) error {
	return re.put(key, value)
}
func (re *emulator) LRange(key string) ([]string, error) {
	return nil, errNotImplemented("LRange")
}
func (re *emulator) LPush(key, value string) error {
	return errNotImplemented("LPush")
}
func (re *emulator) HGet(hKey string, fieldName string) (string, error) {
	re.mu.Lock()
	defer re.mu.Unlock()
	m, ok := re.hKvMap[hKey]
	if !ok || m == nil {
		return "", ErrRedisNil
	}
	return fmt.Sprintf("%v", m[fieldName]), nil
}
func (re *emulator) HSet(hKey string, fieldName string, fieldValue interface{}) error {
	re.mu.Lock()
	defer re.mu.Unlock()
	m, ok := re.hKvMap[hKey]
	if !ok || m == nil {
		m = make(map[string]interface{})
	}
	m[fieldName] = fieldValue
	re.hKvMap[hKey] = m
	return nil
}
func (re *emulator) HMSet(hKey string, fields map[string]interface{}) error {
	for k, v := range fields {
		if err := re.HSet(hKey, k, v); err != nil {
			return err
		}
	}
	return nil
}
func (re *emulator) HDel(hKey string, fieldName string) error {
	re.mu.Lock()
	defer re.mu.Unlock()
	m, ok := re.hKvMap[hKey]
	if !ok || m == nil {
		return nil
	}
	delete(m, fieldName)
	re.hKvMap[hKey] = m
	return nil
}
func (re *emulator) HExists(hKey string, fieldName string) (bool, error) {
	re.mu.Lock()
	defer re.mu.Unlock()
	m, ok := re.hKvMap[hKey]
	if !ok || m == nil {
		return false, nil
	}
	_, ok = m[fieldName]
	return ok, nil
}

func (re *emulator) HGetAll(hKey string) (map[string]string, error) {
	re.mu.Lock()
	defer re.mu.Unlock()

	ret := make(map[string]string)
	m, ok := re.hKvMap[hKey]
	if !ok || m == nil {
		return nil, ErrRedisNil
	}
	for k, v := range m {
		ret[k] = fmt.Sprintf("%v", v)
	}
	return ret, nil
}

func (re *emulator) HScan(hKey string, cursor uint64, match string, count int64) scanCmdInterface {
	return nil
}

func (re *emulator) Scan(cursor uint64, match string, count int64) scanCmdInterface {
	var keys []string
	for k := range re.kvMap {
		matched, err := filepath.Match(match, k)
		if err != nil {
			return &emulatorScanCmd{err: err}
		}
		if matched {
			keys = append(keys, k)
		}
	}
	for k := range re.hKvMap {
		matched, err := filepath.Match(match, k)
		if err != nil {
			return &emulatorScanCmd{err: err}
		}
		if matched {
			keys = append(keys, k)
		}
	}
	if int(cursor) >= len(keys) {
		return &emulatorScanCmd{}
	}
	start := int(cursor)
	stop := int(cursor) + int(count)
	if stop >= len(keys) {
		cursor = 0 // last batch.
		stop = len(keys)
	} else {
		cursor = uint64(stop)
	}

	return &emulatorScanCmd{
		keys:   keys[start:stop],
		cursor: cursor,
	}
}

func (re *emulator) ZAdd(hKey string, score float64, value string) error {
	return errNotImplemented("ZAdd")
}
func (re *emulator) ZRem(hKey string, value interface{}) error {
	return errNotImplemented("ZRam")
}
func (re *emulator) ZRangeWithScore(Key string, start, stop int64) ([]rr.Z, error) {
	return nil, errNotImplemented("ZRangeWithScore")
}
func (re *emulator) ZRange(key string, start, stop int64) ([]string, error) {
	return nil, errNotImplemented("ZRange")
}
func (re *emulator) HLen(key string) (int64, error) {
	return 0, errNotImplemented("HLen")
}

func (re *emulator) get(key string) (string, error) {
	re.mu.Lock()
	defer re.mu.Unlock()

	if v, ok := re.kvMap[key]; ok {
		return v, nil
	}
	return "", ErrRedisNil
}

func (re *emulator) put(key, value string) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.kvMap[key] = value
	return nil
}
func (re *emulator) putWithExpiration(key, value string, _ time.Duration) error {
	return re.put(key, value)
}
func (re *emulator) delete(key string) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	delete(re.kvMap, key)
	delete(re.hKvMap, key)
	return nil
}
