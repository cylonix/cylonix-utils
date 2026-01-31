// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

func fetchGithubUserInfo(
	ctx context.Context, oauth2Config *oauth2.Config, oauth2Token *oauth2.Token,
	log *logrus.Entry,
) ([]byte, error) {
	client := oauth2Config.Client(ctx, oauth2Token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch github user info: %v", err)
	}
	defer resp.Body.Close()
	var user struct {
		Login   string `json:"login"`
		ID      int    `json:"id"`
		Email   string `json:"email"`
		Picture string `json:"avatar_url"`
		Name    string `json:"name"`
	}
	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if (err != nil && !errors.Is(err, io.EOF)) || n <= 0 {
		return nil, fmt.Errorf("failed to read github user info: %v n=%d", err, n)
	}
	buf = buf[:n]
	log.WithField("response", string(buf)).Debugln("Github user info response.")

	json.Unmarshal(buf, &user)
	//json.NewDecoder(resp.Body).Decode(&user)
	rawID := Claims{
		UserID:  fmt.Sprintf("%d", user.ID),
		Name:    user.Name,
		Email:   user.Email,
		Picture: user.Picture,
	}

	// If user has email private, we need to fetch it separately.
	if user.Email == "" {
		emailResp, err := client.Get("https://api.github.com/user/emails")
		if err != nil {
			return nil, fmt.Errorf("failed to fetch github user emails: %v", err)
		}
		defer emailResp.Body.Close()
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := json.NewDecoder(emailResp.Body).Decode(&emails); err != nil {
			return nil, fmt.Errorf("failed to decode github user emails: %v", err)
		}
		for _, e := range emails {
			if e.Primary && e.Verified {
				rawID.Email = e.Email
				break
			}
		}
	}

	v, err := json.Marshal(rawID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal github user info: %v", err)
	}
	log.WithField("github_user", user.Login).Debugln("Fetched github user info.")
	return v, nil
}
