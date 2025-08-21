// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sendmail

import (
	"fmt"
	"time"

	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"
	gviper "github.com/spf13/viper"
)

const (
	idleTime        = time.Minute * 5
)

type SendmailInterface interface {
	From() string
	EmailClient
}

var (
	instance SendmailInterface
)

type Emulator struct{}

func (e *Emulator) From() string {
	return "emulator"
}

func (e *Emulator) Send(from, subject, body string, to, cc, bcc []string) error {
	return nil
}
func (e *Emulator) Quit() error {
	return nil
}

type Impl struct {
	client  EmailClient
	setting *Setting
	ticker  *time.Ticker
	log     *logrus.Entry
}

func NewEmulator() (*Emulator, error) {
	return &Emulator{}, nil
}

func SetInstance(i SendmailInterface) {
	instance = i
}

func Init(viper *gviper.Viper, logger *logrus.Entry) error {
	InitSetting(viper)
	if instance != nil {
		return fmt.Errorf("instance already set to type: %T", instance)
	}
	setting := LoadSetting()
	if !setting.Valid() {
		return fmt.Errorf("invalid send email setting: %v", setting)
	}
	log := logger.WithField(ulog.SubSys, "sendemail")
	instance = &Impl{
		setting: setting,
		log:     logger.WithField(ulog.SubSys, "sendemail"),
	}

	log.WithField("service-account", setting.ServiceAccountFile).
		WithField("provider", setting.Provider).
		WithField("from", setting.From).
		Infoln("Setting initialized.")
	return nil
}

func (i *Impl) startClient() error {
	setting, log := i.setting, i.log
	i.log.Debugln("Starting a new email client.")
	if i.client != nil {
		log.Debugln("Email client already started.")
		return nil
	}
	// Create a new email client.
	client, err := NewClient(setting.Provider, setting.From, setting.ServiceAccountFile)
	if err != nil {
		log.WithError(err).Errorln("Failed to create email client.")
		return fmt.Errorf("failed to create email client: %w", err)
	}
	i.client = client

	// Start a background cleaner to disconnect if there is no email sent
	// for the idle time setting.
	i.ticker = time.NewTicker(idleTime)
	go func() {
		<-i.ticker.C
		if i.client != nil {
			log.Debugln("Stopping the email sender.")
			if err := i.client.Quit(); err != nil {
				log.WithError(err).Errorln("Failed to close email sender.")
			}
			i.ticker.Stop()
			i.client = nil
			i.ticker = nil
		}
	}()
	log.Debugln("Started the new email client successfully.")
	return nil
}

func (i *Impl) From() string {
	return i.setting.From
}

func (i *Impl) Send(from, subject, body string, to, cc, bcc []string) error {
	if err := i.startClient(); err != nil {
		return fmt.Errorf("failed to start email client: %w", err)
	}
	if err := i.client.Send(from, subject, body, to, cc, bcc); err != nil {
		i.log.WithError(err).Errorln("Failed to send email.")
		return fmt.Errorf("failed to send email: %w", err)
	}
	i.log.WithField("to", to).Debugln("Email sent successfully.")
	return nil
}

func (i *Impl) Quit() error {
	return i.client.Quit()
}

func SendEmail(to []string, subject, body string) error {
	return instance.Send(instance.From(), subject, body, to, nil, nil)
}
