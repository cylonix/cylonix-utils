// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package redis

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	rr "github.com/go-redis/redis"
)

const (
	ObjTypeUserProfile        = "user_profile"
	ObjTypeUserFriends        = "user_friends"
	ObjTypeUserFriendRequests = "user_friend_requests"
)

type scanCmdInterface interface {
	Result() ([]string, uint64, error)
}

type ClientInterface interface {
	SetWithExpiration(key, value string, expiration time.Duration) error
	Set(key, value string) error
	Get(key string) (string, error)
	Del(key string) error
	LPush(key, value string) error
	LRange(key string) ([]string, error)
	LRem(key string, count int64, value string) error
	HExists(hKey, fieldName string) (bool, error)
	HGet(hKey, value string) (string, error)
	HSet(hKey, fieldName string, fieldValue interface{}) error
	HMSet(hKey string, fields map[string]interface{}) error
	HDel(hKey, fieldName string) error
	HGetAll(hKey string) (map[string]string, error)
	HScan(hKey string, cursor uint64, match string, count int64) scanCmdInterface
	Scan(cursor uint64, match string, count int64) scanCmdInterface
	ZAdd(hKey string, score float64, value string) error
	ZRem(hKey string, value interface{}) error
	ZRangeWithScore(key string, start, stop int64) ([]rr.Z, error)
	ZRange(key string, start, stop int64) ([]string, error)
	HLen(key string) (int64, error)
}

type Client struct {
	config    *rr.Options
	redisConn *rr.Client
}

var (
	redisInstance      ClientInterface
	ErrInstanceIsNil   = errors.New("redis instance not initialized")
	ErrFailedToConnect = errors.New("failed to connect to redis")
	ErrRedisNil        = rr.Nil
	ErrEntryIsEmpty    = errors.New("entry is empty")
	ShortExpiration    = time.Duration(time.Minute)
	LongExpiration     = time.Duration(time.Hour)
	rootDomain         string
)

func newClient(addr, password string) (*Client, error) {
	proto, ipAndPort := "", addr
	tmp := strings.SplitN(addr, "://", 2)
	if len(tmp) == 2 {
		proto = tmp[0] // tcp/unix
		ipAndPort = tmp[1]
	}
	config := &rr.Options{
		Network:  proto,
		Addr:     ipAndPort,
		Password: password,
		DB:       0,
	}
	return &Client{
		config:    config,
		redisConn: rr.NewClient(config),
	}, nil
}

func (c *Client) set(key, value string, expiration time.Duration) error {
	return c.redisConn.Set(key, value, expiration).Err()
}

func (c *Client) Set(key, value string) error {
	return c.set(key, value, 0)
}
func (c *Client) LPush(key, value string) error {
	return c.redisConn.LPush(key, value).Err()
}
func (c *Client) LRange(key string) ([]string, error) {
	return c.redisConn.LRange(key, 0, -1).Result()
}
func (c *Client) LRem(key string, count int64, value string) error {
	return c.redisConn.LRem(key, count, value).Err()
}
func (c *Client) HGet(hKey, fieldName string) (string, error) {
	return c.redisConn.HGet(hKey, fieldName).Result()
}
func (c *Client) HSet(hKey, fieldName string, fieldValue interface{}) error {
	return c.redisConn.HSet(hKey, fieldName, fieldValue).Err()
}
func (c *Client) HMSet(hKey string, fields map[string]interface{}) error {
	return c.redisConn.HMSet(hKey, fields).Err()
}
func (c *Client) HDel(hKey, fieldName string) error {
	return c.redisConn.HDel(hKey, fieldName).Err()
}
func (c *Client) HExists(hKey, fieldName string) (bool, error) {
	yes, err := c.redisConn.HExists(hKey, fieldName).Result()
	if err == nil {
		return yes, nil
	}
	if errors.Is(err, ErrRedisNil) {
		return false, nil
	}
	return false, err
}
func (c *Client) HGetAll(hKey string) (map[string]string, error) {
	m, err := c.redisConn.HGetAll(hKey).Result()
	if err != nil {
		return nil, err
	}
	if len(m) <= 0 {
		return nil, ErrRedisNil
	}
	return m, nil
}
func (c *Client) HLen(hKey string) (int64, error) {
	return c.redisConn.HLen(hKey).Result()
}
func (c *Client) ZAdd(hKey string, score float64, value string) error {
	obj := rr.Z{
		Score:  score,
		Member: value,
	}
	return c.redisConn.ZAdd(hKey, obj).Err()
}
func (c *Client) ZRem(hKey string, value interface{}) error {
	return c.redisConn.ZRem(hKey, value).Err()
}
func (c *Client) ZRangeWithScore(Key string, start int64, stop int64) ([]rr.Z, error) {
	return c.redisConn.ZRangeWithScores(Key, start, stop).Result()
}

func (c *Client) ZRange(Key string, start int64, stop int64) ([]string, error) {
	return c.redisConn.ZRange(Key, start, stop).Result()
}
func (c *Client) Get(key string) (string, error) {
	return c.redisConn.Get(key).Result()
}
func (c *Client) Del(key string) error {
	_, err := c.redisConn.Del(key).Result()
	return err
}

func (c *Client) SetWithExpiration(key, value string, expiration time.Duration) error {
	return c.set(key, value, expiration)
}

func (c *Client) HScan(hKey string, cursor uint64, match string, count int64) scanCmdInterface {
	return c.redisConn.HScan(hKey, cursor, match, count)
}

func (c *Client) Scan(cursor uint64, match string, count int64) scanCmdInterface {
	return c.redisConn.Scan(cursor, match, count)
}

func Init(addr, password, prefix string) error {
	rootDomain = prefix
	redis, err := newClient(addr, password)
	if err != nil {
		return fmt.Errorf("new redis client failed: %w", err)
	}

	SetImpl(redis)
	return nil
}

func GetImpl() ClientInterface {
	return redisInstance
}

func SetImpl(redis ClientInterface) {
	redisInstance = redis
}

func Put(namespace, objectType, id, value string) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.Set(key, value)
}
func PutWithExpiration(namespace, objectType, id, value string, expiration time.Duration) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.SetWithExpiration(key, value, expiration)
}

func PutWithKeyWithExpiration(key, value string, expiration time.Duration) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	return redisInstance.SetWithExpiration(key, value, expiration)
}
func Get(namespace, objectType, id string) (string, error) {
	if redisInstance == nil {
		return "", ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.Get(key)
}

func GetWithKey(key string) (string, error) {
	return redisInstance.Get(key)
}

func Delete(namespace, objectType, id string) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.Del(key)
}
func DeleteWithKey(key string) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	return redisInstance.Del(key)
}
func LPush(namespace, objectType, id, value string) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.LPush(key, value)
}
func DeleteListItem(namespace, objectType, id, value string) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.LRem(key, 1, value)
}
func HGet(namespace, objectType, id, value string) (string, error) {
	if redisInstance == nil {
		return "", ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.HGet(key, value)
}
func HLen(namespace, objectType, id string) (int64, error) {
	if redisInstance == nil {
		return 0, ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.HLen(key)
}
func HSet(namespace, objectType, id, fieldName string, fieldValue interface{}) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.HSet(key, fieldName, fieldValue)
}
func HDel(namespace, objectType, id, fieldName string) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.HDel(key, fieldName)
}
func HExists(namespace, objectType, id, fieldName string) (bool, error) {
	if redisInstance == nil {
		return false, ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.HExists(key, fieldName)
}
func HGetAll(namespace, objectType, id string) (map[string]string, error) {
	key := Key(namespace, objectType, id)
	return HGetAllWithKey(key)
}
func HGetAllWithKey(key string) (map[string]string, error) {
	if redisInstance == nil {
		return nil, ErrInstanceIsNil
	}
	return redisInstance.HGetAll(key)
}
func HMSet(namespace, objectType, id string, fields map[string]interface{}) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.HMSet(key, fields)
}
func HMSetWithKey(key string, fields map[string]interface{}) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	return redisInstance.HMSet(key, fields)
}
func ZAdd(namespace, objectType, id string, score float64, value string) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.ZAdd(key, score, value)
}
func ZRem(namespace, objectType, id string, value interface{}) error {
	if redisInstance == nil {
		return ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.ZRem(key, value)
}
func ZRangeWithScore(namespace, objectType, id string, start int64, stop int64) ([]rr.Z, error) {
	if redisInstance == nil {
		return nil, ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.ZRangeWithScore(key, start, stop)
}
func ZRange(namespace, objectType, id string, start int64, stop int64) ([]string, error) {
	if redisInstance == nil {
		return nil, ErrInstanceIsNil
	}
	key := Key(namespace, objectType, id)
	return redisInstance.ZRange(key, start, stop)
}
func Key(namespace, objectType, id string) string {
	return GenerateID(namespace, objectType, id)
}
func Scan(match string, cursor uint64, count int64) scanCmdInterface {
	return redisInstance.Scan(cursor, match, count)
}

func RootDomain() string {
	if rootDomain != "" {
		return rootDomain
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "cylonix-manager"
	}
	return hostname + "-redis"
}

func GenerateID(namespace, objectType string, keys ...string) string {
	return fmt.Sprintf("/%v/%v/%v/%v", RootDomain(), namespace, objectType, strings.Join(keys, "/"))
}
