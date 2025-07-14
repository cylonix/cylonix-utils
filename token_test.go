// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils_test

import (
	"testing"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/etcd"
	"github.com/cylonix/utils/postgres"
	"github.com/stretchr/testify/assert"
)

func setupTest(verbose bool) error {
	utils.Init(nil)
	etcdE, err := etcd.NewEmulator()
	if err != nil {
		return err
	}
	etcd.SetImpl(etcdE)
	postgres.SetEmulator(true, verbose)
	if err := postgres.AutoMigrate(&utils.UserTokenData{}); err != nil {
		return err
	}
	return nil
}

func TestUserToken(t *testing.T) {
	if !assert.Nil(t, setupTest(testing.Verbose())) {
		return
	}
	namespace := "test-user-token-namespace"
	username := "test-user-token-username"
	token := utils.NewUserToken(namespace)
	tokenData := &utils.UserTokenData{
		Token: token.Token,
		Namespace: namespace,
		Username: username,
	}
	if !assert.Nil(t, token.Create(tokenData)) {
		return
	}
	to := &utils.UserToken{Token: token.Token}
	data := &utils.UserTokenData{}
	assert.Nil(t, to.Get(data))
	if assert.NotNil(t, data) {
		assert.Equal(t, username, data.Username)
	}
}
