// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package paging

func startStop(page, pageSize, total int) (start int, stop int) {
	if total < 1 {
		return
	}
	stop = total
	if pageSize < 1 {
		return
	}
	if page < 1 {
		start = 0
	} else {
		start = (page - 1) * pageSize
		if start >= total {
			start = stop
			return
		}
	}
	if (total - start) > pageSize {
		stop = start + pageSize
	}
	return
}

func StartStop[T int|int64|uint64](pageP, pageSizeP *T, total int) (start int, stop int) {
	if pageP == nil || pageSizeP == nil || *pageP < 0 || *pageSizeP <= 0 {
		return 0, total
	}
	return startStop(int(*pageP), int(*pageSizeP), total)
}
