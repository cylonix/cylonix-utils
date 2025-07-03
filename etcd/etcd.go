package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	PrefixName          = "etcd-prefix"
	etcdDialTimeout     = 5 * time.Second
	cacheExpirationTime = time.Duration(time.Second * 1800)
)

var (
	etcdDebugKey         = os.Getenv("SASE_ETCD_DEBUG_KEY")
	ErrNilID             = errors.New("nil id")
	ErrDataNotExists     = errors.New("data is not in db")
	ErrInstanceNotExists = errors.New("etcd instance does not exist")
	ErrFailedToConnect   = errors.New("failed to connect to etcd")
)

type watchFunc func(*clientv3.Event) error

type cache struct {
	key        string
	resp       *clientv3.GetResponse
	elapseTime time.Time
}
type ClientInterface interface {
	Put(namespace, objectType, id, value string) error
	PutWithKey(key, value string) error
	Get(namespace, objectType, id string) (*clientv3.GetResponse, error)
	GetNoCache(namespace, objectType, id string) (*clientv3.GetResponse, error)
	GetAll(namespace, objectType string) (*clientv3.GetResponse, error)
	GetWithPrefix(prefix string) (*clientv3.GetResponse, error)
	GetWithPagination(namespace, objectType, lastKey string, pageSize int) (*clientv3.GetResponse, error)
	GetWithKey(key string) (*clientv3.GetResponse, error)
	GetWithKeyNoCache(key string) (*clientv3.GetResponse, error)
	Delete(namespace, objectType, id string) error
	DeleteWithKey(key string) error
	GetData(key string, data interface{}) error
	Watch(context.Context, string, watchFunc, *logrus.Entry) error
}

var (
	etcdCache    sync.Map
	etcdClient   *clientv3.Client
	etcdInstance ClientInterface
	etcdPrefix   string
)

func (c *client) deleteCache(key string) error {
	if _, ok := etcdCache.Load(key); ok {
		etcdCache.Delete(key)
		if key == etcdDebugKey {
			c.logger.WithField("key", key).Infoln("delete in cache")
		}
	}
	return nil
}

type client struct {
	config *clientv3.Config
	logger *logrus.Entry
}

func newClient(endpoints []string, logger *logrus.Entry) (*client, error) {
	config := &clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: etcdDialTimeout,
	}
	return &client{
		config: config,
		logger: logger.WithField("subsys", "etcd"),
	}, nil
}

func (c *client) connect() (*clientv3.Client, error) {
	if etcdClient != nil {
		return etcdClient, nil
	}

	ret, err := clientv3.New(*c.config)
	if err != nil {
		return nil, err
	}

	etcdClient = ret
	return etcdClient, nil
}

func (c *client) newKV() (clientv3.KV, error) {
	cc, err := c.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to etcd: %w", err)
	}
	return clientv3.NewKV(cc), nil
}

func (c *client) Put(namespace, objectType, id, value string) error {
	if id == "" {
		return ErrNilID
	}
	key := GenerateID(namespace, objectType, id)
	return c.PutWithKey(key, value)
}

func (c *client) PutWithKey(key, value string) error {
	if key == etcdDebugKey {
		c.debugLog("put-with-key", value, "")
	}

	if _, err := c.put(key, value, clientv3.WithPrevKV()); err != nil {
		return err
	}
	if len(value) == 0 {
		if key == etcdDebugKey {
			c.debugLog("put-with-key", value, "empty data put into etcd")
		}
	}
	c.deleteCache(key)
	return nil
}

func (c *client) Get(namespace, objectType, id string) (*clientv3.GetResponse, error) {
	key := GenerateID(namespace, objectType, id)
	return c.GetWithKey(key)
}
func (c *client) GetNoCache(namespace, objectType, id string) (*clientv3.GetResponse, error) {
	key := GenerateID(namespace, objectType, id)
	return c.GetWithKeyNoCache(key)
}
func (c *client) GetData(key string, data interface{}) error {
	resp, err := c.GetWithKey(key)
	if err != nil {
		return err
	}
	if len(resp.Kvs) > 0 && len(resp.Kvs[0].Value) > 0 {
		return json.Unmarshal(resp.Kvs[0].Value, data)
	}
	return ErrDataNotExists
}
func (c *client) GetWithKeyNoCache(key string) (*clientv3.GetResponse, error) {
	getResp, err := c.get(key)
	if err != nil {
		return nil, err
	}
	return getResp, nil
}
func (c *client) debugLog(handle, value, msg string) {
	c.logger.WithFields(logrus.Fields{
		ulog.Key:       etcdDebugKey,
		ulog.Value:     value,
		ulog.SubHandle: handle,
		ulog.SubSys:    "etcd",
	}).Infoln("DEBUG: " + msg)
}
func (c *client) errorLog(handle, key string, err error) {
	c.logger.WithFields(logrus.Fields{
		ulog.Key:       key,
		ulog.SubHandle: handle,
		ulog.SubSys:    "etcd",
	}).WithError(err).Errorln("ERROR")
}
func (c *client) get(key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	kv, err := c.newKV()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), etcdDialTimeout)
	defer cancel()
	getResp, err := kv.Get(ctx, key, opts...)
	if err != nil {
		c.errorLog("get", key, err)
		return nil, err
	}
	return getResp, nil
}
func (c *client) delete(key string, opts ...clientv3.OpOption) (*clientv3.DeleteResponse, error) {
	kv, err := c.newKV()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), etcdDialTimeout)
	defer cancel()
	deleteResp, err := kv.Delete(ctx, key, opts...)
	if err != nil {
		c.errorLog("delete", key, err)
		return nil, err
	}
	return deleteResp, nil
}
func (c *client) put(key, val string, opts ...clientv3.OpOption) (*clientv3.PutResponse, error) {
	kv, err := c.newKV()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), etcdDialTimeout)
	defer cancel()
	putResp, err := kv.Put(ctx, key, val, opts...)
	if err != nil {
		c.errorLog("put", key, err)
		return nil, err
	}
	return putResp, nil
}
func (c *client) GetWithKey(key string) (*clientv3.GetResponse, error) {
	if key == etcdDebugKey {
		c.debugLog("get-with-key", "", "")
	}
	if value, ok := etcdCache.Load(key); ok {
		cache := value.(*cache)
		if cache.elapseTime.After(time.Now()) {
			if cache.resp == nil || cache.resp.Kvs == nil || len(cache.resp.Kvs) == 0 {
				if key == etcdDebugKey {
					c.debugLog("get-with-key", "", "no data in cache")
				}
			}
			return cache.resp, nil
		}
		c.deleteCache(key)
	}
	getResp, err := c.get(key)
	if err != nil {
		return nil, err
	}

	if key == etcdDebugKey {
		c.debugLog("get-with-key", "", "read data from etcd directly")
	}
	if len(getResp.Kvs) > 0 {
		cache := &cache{
			elapseTime: time.Now().Add(cacheExpirationTime),
			resp:       getResp,
			key:        key,
		}
		etcdCache.Store(key, cache)
	} else {
		if key == etcdDebugKey {
			c.debugLog("get-with-key", "", "no data in etcd")
		}
	}

	return getResp, nil
}

func (c *client) GetAll(namespace, objectType string) (*clientv3.GetResponse, error) {
	id := fmt.Sprintf("/%v/%v/%v/", RootDomain(), namespace, objectType)
	return c.GetWithPrefix(id)
}

func (c *client) GetWithPrefix(prefix string) (*clientv3.GetResponse, error) {
	getResp, err := c.get(prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}
	return getResp, nil
}

func (c *client) GetWithPagination(namespace, objectType, lastKey string, pageSize int) (getResp *clientv3.GetResponse, err error) {
	if lastKey != "" {
		pageSize += 1
	}

	prefix := fmt.Sprintf("/%v/%v/%v/", RootDomain(), namespace, objectType)
	if lastKey == "" {
		getResp, err = c.get(prefix,
			clientv3.WithPrefix(),
			clientv3.WithLimit(int64(pageSize)))
	} else {
		prefix = fmt.Sprintf("%v/%v", prefix, lastKey)
		getResp, err = c.get(prefix,
			clientv3.WithFromKey(),
			clientv3.WithPrefix(),
			clientv3.WithLimit(int64(pageSize)))
	}
	if err != nil {
		return nil, err
	}

	if lastKey != "" {
		if len(getResp.Kvs) > 2 {
			getResp.Kvs = getResp.Kvs[1:]
		} else {
			getResp.Kvs = make([]*mvccpb.KeyValue, 0)
		}
	}

	return getResp, nil
}
func (c *client) DeleteWithKey(key string) error {
	if key == etcdDebugKey {
		c.debugLog("del-with-key", "", "")
	}
	delResp, err := c.delete(key, clientv3.WithPrefix())
	if err != nil {
		return err
	}
	if len(delResp.PrevKvs) != 0 {
		if key == etcdDebugKey {
			c.debugLog("del-with-key", "", "failed to delete")
		}
		return nil
	}

	c.deleteCache(key)
	return nil
}

func (c *client) Delete(namespace, objectType, id string) error {
	key := GenerateID(namespace, objectType, id)
	return c.DeleteWithKey(key)
}

func (c *client) Watch(ctx context.Context, prefix string, callback watchFunc, log *logrus.Entry) error {
	client, err := c.connect()
	if err != nil {
		log.WithError(err).Errorf("failed to connect to ETCD")
		return fmt.Errorf("failed to connect to etcd: %w", err)
	}

	log.Infoln("start to watch ETCD:", prefix)
	watchChan := client.Watch(ctx, prefix, clientv3.WithPrefix())
	go func() {
		for resp := range watchChan {
			if resp.Err() != nil {
				log.WithError(resp.Err()).Errorf("failed to watch etcd")
				return
			}
			if resp.Canceled {
				log.Errorf("etcd watch is canceled")
				return
			}

			for _, event := range resp.Events {
				callback(event)
			}
		}
	}()

	return nil
}

func Init(prefix string, endpoints []string, logger *logrus.Entry) error {
	logger.WithFields(logrus.Fields{
		"prefix":    prefix,
		"handle":    "etcd init",
		"endpoints": endpoints,
	}).Infoln("Init")
	etcdPrefix = prefix
	client, err := newClient(endpoints, logger)
	if err != nil {
		return err
	}
	SetImpl(client)
	return nil
}

func SetImpl(etcd ClientInterface) {
	etcdInstance = etcd
}

func Put(namespace, objectType, id, value string) error {
	if etcdInstance == nil {
		return ErrInstanceNotExists
	}
	return etcdInstance.Put(namespace, objectType, id, value)
}

func PutWithKey(key, value string) error {
	if etcdInstance == nil {
		return ErrInstanceNotExists
	}
	return etcdInstance.PutWithKey(key, value)
}

func Get(namespace, objectType, id string) (*clientv3.GetResponse, error) {
	if etcdInstance == nil {
		return nil, ErrInstanceNotExists
	}
	return etcdInstance.Get(namespace, objectType, id)
}
func GetNoCache(namespace, objectType, id string) (*clientv3.GetResponse, error) {
	if etcdInstance == nil {
		return nil, ErrInstanceNotExists
	}
	return etcdInstance.GetNoCache(namespace, objectType, id)
}
func GetData(key string, data interface{}) error {
	if etcdInstance == nil {
		return ErrInstanceNotExists
	}
	return etcdInstance.GetData(key, data)
}

func GetWithKey(key string) (*clientv3.GetResponse, error) {
	if etcdInstance == nil {
		return nil, ErrInstanceNotExists
	}
	return etcdInstance.GetWithKey(key)
}

func GetAll(namespace, objectType string) (*clientv3.GetResponse, error) {
	if etcdInstance == nil {
		return nil, ErrInstanceNotExists
	}
	return etcdInstance.GetAll(namespace, objectType)
}

func GetWithPagination(namespace, objectType, lastKey string, pageSize int) (*clientv3.GetResponse, error) {
	if etcdInstance == nil {
		return nil, ErrInstanceNotExists
	}

	return etcdInstance.GetWithPagination(namespace, objectType, lastKey, pageSize)
}

func GetWithPrefix(prefix string) (*clientv3.GetResponse, error) {
	if etcdInstance == nil {
		return nil, ErrInstanceNotExists
	}
	return etcdInstance.GetWithPrefix(prefix)
}

func Delete(namespace, objectType, id string) error {
	if etcdInstance == nil {
		return ErrInstanceNotExists
	}
	return etcdInstance.Delete(namespace, objectType, id)
}

func DeleteWithKey(key string) error {
	if etcdInstance == nil {
		return ErrInstanceNotExists
	}
	return etcdInstance.DeleteWithKey(key)
}

func Watch(ctx context.Context, prefix string, callback watchFunc, log *logrus.Entry) error {
	if etcdInstance == nil {
		return ErrInstanceNotExists
	}
	return etcdInstance.Watch(ctx, prefix, callback, log)
}

func RootDomain() string {
	if etcdPrefix != "" {
		return etcdPrefix
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "sase-manager"
	}
	return hostname + "-etcd"
}

func GenerateID(namespace, objectType, key string) string {
	return fmt.Sprintf("/%v/%v/%v/%v", RootDomain(), namespace, objectType, key)
}
