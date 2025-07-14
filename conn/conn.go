// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package conn

import (
	"fmt"
	"io"
	"net/http"
)

func ParseErrResponse(rsp *http.Response, err error) error {
	if rsp != nil {
		v, _ := io.ReadAll(rsp.Body)
		err = fmt.Errorf("%w: %v", err, string(v))
	}
	return err
}


