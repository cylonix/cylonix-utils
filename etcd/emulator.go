// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type emulator struct {
	kvMap map[string]string
}

func NewEmulator() (ClientInterface, error) {
	return &emulator{kvMap: make(map[string]string)}, nil
}

func (etcd *emulator) Get(namespace, objectType, id string) (*clientv3.GetResponse, error) {
	return etcd.get(GenerateID(namespace, objectType, id))
}
func (etcd *emulator) GetNoCache(namespace, objectType, id string) (*clientv3.GetResponse, error) {
	return etcd.get(GenerateID(namespace, objectType, id))
}
func (etcd *emulator) get(key string) (*clientv3.GetResponse, error) {
	var kvs []*mvccpb.KeyValue
	count := 0
	if v, ok := etcd.kvMap[key]; ok {
		kvs = []*mvccpb.KeyValue{
			{
				Key:            []byte(key),
				CreateRevision: 0,
				ModRevision:    0,
				Version:        0,
				Value:          []byte(v),
				Lease:          0,
			},
		}
		count = 1
	}
	return &clientv3.GetResponse{
		Header: nil,
		Kvs:    kvs,
		More:   false,
		Count:  int64(count),
	}, nil
}

func (etcd *emulator) put(key, value string) error {
	etcd.kvMap[key] = value
	return nil
}

func (etcd *emulator) Put(namespace, objectType, id, value string) error {
	return etcd.put(GenerateID(namespace, objectType, id), value)
}

func (etcd *emulator) PutWithKey(key, value string) error {
	return etcd.put(key, value)
}

func (etcd *emulator) GetAll(namespace, objectType string) (*clientv3.GetResponse, error) {
	return etcd.GetWithPrefix(GenerateID(namespace, objectType, ""))
}
func (etcd *emulator) GetData(key string, data interface{}) error {
	resp, err := etcd.GetWithKey(key)
	if err != nil {
		return err
	}
	if len(resp.Kvs) > 0 && len(resp.Kvs[0].Value) > 0 {
		return json.Unmarshal(resp.Kvs[0].Value, data)
	}
	return ErrDataNotExists
}
func (etcd *emulator) GetWithPrefix(prefix string) (*clientv3.GetResponse, error) {
	var kvList []*mvccpb.KeyValue
	count := 0
	for k, v := range etcd.kvMap {
		if strings.HasPrefix(k, prefix) {
			kvList = append(kvList, &mvccpb.KeyValue{
				Key:            []byte(k),
				CreateRevision: 0,
				ModRevision:    0,
				Version:        0,
				Value:          []byte(v),
				Lease:          0,
			})
			count++
		}
	}
	return &clientv3.GetResponse{
		Header: nil,
		Kvs:    kvList,
		More:   false,
		Count:  int64(count),
	}, nil
}
func (etcd *emulator) delete(key string) error {
	delete(etcd.kvMap, key)
	return nil
}

// Delete delete the entry and does not return error if entry does not exists.
func (etcd *emulator) Delete(namespace, objectType, id string) error {
	key := GenerateID(namespace, objectType, id)
	return etcd.delete(key)
}

func (etcd *emulator) DeleteWithKey(key string) error {
	return etcd.delete(key)
}

func (etcd *emulator) GetWithKey(key string) (*clientv3.GetResponse, error) {
	return etcd.get(key)
}
func (etcd *emulator) GetWithKeyNoCache(key string) (*clientv3.GetResponse, error) {
	return etcd.get(key)
}
func (etcd *emulator) GetWithPagination(
	namespace, objectType, lastKey string,
	pageSize int,
) (*clientv3.GetResponse, error) {
	if lastKey == "" {
		// Use get all for now
		return etcd.GetAll(namespace, objectType)
	}
	return nil, errors.New("not yet implemented")
}

func (etcd *emulator) Watch(ctx context.Context, prefix string, callback watchFunc, log *logrus.Entry) error {
	return nil
}
