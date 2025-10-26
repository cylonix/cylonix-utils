// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sendmail

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

type EmailClient interface {
	Send(from, subject, body string, to, cc, bcc []string) error
	Quit() error
}

type GmailClient struct {
    service *gmail.Service
}

func NewClient(provider, from, serviceAccountFile string) (EmailClient, error) {
    if provider != "google" {
        return nil, fmt.Errorf("unsupported email provider: %s, only 'google' is supported", provider)
    }

    ctx := context.Background()
    data, err := os.ReadFile(serviceAccountFile)
    if err != nil {
        return nil, fmt.Errorf("reading service account file: %v", err)
    }

    config, err := google.JWTConfigFromJSON(data, gmail.GmailSendScope)
    if err != nil {
        return nil, fmt.Errorf("parsing service account JSON: %v", err)
    }
	config.Subject = from

    ts := config.TokenSource(ctx)
    srv, err := gmail.NewService(ctx, option.WithTokenSource(ts))
    if err != nil {
        return nil, fmt.Errorf("creating Gmail service: %v", err)
    }

    return &GmailClient{
        service: srv,
    }, nil
}

func (c *GmailClient) Send(from, subject, body string, to, cc, bcc []string) error {
    var message gmail.Message

    // Create email headers
    headers := make([]string, 0)
    headers = append(headers, fmt.Sprintf("From: %s", from))
    headers = append(headers, fmt.Sprintf("To: %s", strings.Join(to, ",")))
    if len(cc) > 0 {
        headers = append(headers, fmt.Sprintf("Cc: %s", strings.Join(cc, ",")))
    }
    headers = append(headers, fmt.Sprintf("Subject: %s", subject))
	headers = append(headers, "MIME-Version: 1.0")
    headers = append(headers, "Content-Type: text/html; charset=UTF-8")

    // Create email body
    emailBody := append(headers, "", body)
    msgStr := strings.Join(emailBody, "\r\n")

    // Encode the email
    msg := []byte(msgStr)
    message.Raw = base64.URLEncoding.EncodeToString(msg)

    // Send the email
    _, err := c.service.Users.Messages.Send("me", &message).Do()
    if err != nil {
        return fmt.Errorf("failed to send email: %v", err)
    }

    return nil
}

func (c *GmailClient) Quit() error {
    // No need to implement for Gmail API
    return nil
}
