package influxdb

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
)

const (
	influxdbDefaultOrg = "cylonix"
)

var (
	client            influxdb2.Client
	logger            = logrus.New().WithField("sub-sys", "influxdb")
	ErrClientNotReady = errors.New("client not ready")
	ErrNotFound       = errors.New("not found")
)

type TimeValue struct {
	Timestamp string
	Value     float64
}

func NewClient(host, port, token string) (influxdb2.Client, error) {
	if client == nil {
		client = influxdb2.NewClient("http://"+host+":"+port, token)
	}
	return client, nil
}

func GetClient() (influxdb2.Client, error) {
	if client == nil {
		return nil, ErrClientNotReady
	}
	return client, nil
}

func Query(query string) (*api.QueryTableResult, error) {
	client, err := GetClient()
	if err != nil || client == nil {
		return nil, ErrClientNotReady
	}
	queryAPI := client.QueryAPI(influxdbDefaultOrg)
	return queryAPI.Query(context.Background(), query)
}

// TODO: look into how to get the last value without loop.
func LastValue(query string) (float64, error) {
	result, err := Query(query)
	if err != nil {
		return 0, err
	}

	var val float64
	var found bool
	for result.Next() {
		value := result.Record().Value()
		logger.Debugf("get value:%v %v %v %v\n",
			result.Record().Time(),
			result.Record().Field(),
			result.Record().Value(),
			result.Record().ValueByKey("host"),
		)
		switch v := value.(type) {
		case int64:
			val = float64(v)
		case float64:
			val = v
		default:
			continue
		}
	}
	if !found {
		return 0, ErrNotFound
	}
	return val, nil
}

func ListValue(query string) ([]*TimeValue, error) {
	result, err := Query(query)
	if err != nil {
		return nil, err
	}

	var (
		rawDataList []*TimeValue
		val         float64
		log         = logger.WithField("query", query)
	)
	for result.Next() {
		value := result.Record().Value()
		log.Debugf("get value:%v %v %v %v\n",
			result.Record().Time(),
			result.Record().Field(),
			result.Record().Value(),
			result.Record().ValueByKey("host"),
		)
		switch v := value.(type) {
		case int64:
			val = float64(v)
		case float64:
			val = v
		default:
			continue
		}

		rawDataList = append(rawDataList, &TimeValue{
			Timestamp: result.Record().Time().String(),
			Value:     val,
		})
	}
	if len(rawDataList) <= 0 {
		return nil, ErrNotFound
	}
	return rawDataList, nil
}
