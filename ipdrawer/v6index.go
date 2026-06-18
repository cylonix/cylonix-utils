// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipdrawer

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"

	"github.com/cylonix/utils/etcd"
)

// IPv6 node addresses are globally unique across namespaces (unlike IPv4, which
// overlaps per namespace only because the CGNAT /10 is too small to partition).
// Within the Tailscale ULA /48 (fd7a:115c:a1e0::/48) each namespace gets a
// distinct /96, selected by a stable 48-bit index. The low 32 bits are the
// per-node host, kept <= 2^32 so ipdrawer can allocate them randomly. The
// namespace->index mapping is assigned once and persisted in etcd (collision
// free via compare-and-swap on a monotonic counter), then cached in process.
const (
	v6IndexBits = 48
	v6MaxIndex  = (uint64(1) << v6IndexBits) - 1

	v6IndexMaxRetries = 32
)

var (
	// The /48 prefix bytes: fd7a:115c:a1e0.
	v6PrefixBytes = [6]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0}

	// In-process cache of namespace -> index. Indices are stable once assigned,
	// so this never needs invalidation.
	v6IndexCache sync.Map // string -> uint64

	ErrV6IndexExhausted = errors.New("ipv6 namespace index space exhausted")
)

func v6IndexCounterKey() string {
	return etcd.GenerateID("_global", "v6_ns_index_counter", "v1")
}

func v6IndexNamespaceKey(namespace string) string {
	return etcd.GenerateID("_global", "v6_ns_index", namespace)
}

// namespaceV6Index returns the stable per-namespace index, assigning the next
// free one on first use.
func namespaceV6Index(namespace string) (uint64, error) {
	if v, ok := v6IndexCache.Load(namespace); ok {
		return v.(uint64), nil
	}
	nsKey := v6IndexNamespaceKey(namespace)
	if idx, ok, err := readV6Index(nsKey); err != nil {
		return 0, err
	} else if ok {
		v6IndexCache.Store(namespace, idx)
		return idx, nil
	}
	idx, err := assignV6Index(nsKey)
	if err != nil {
		return 0, err
	}
	v6IndexCache.Store(namespace, idx)
	return idx, nil
}

func readV6Index(key string) (uint64, bool, error) {
	resp, err := etcd.GetWithKeyNoCache(key)
	if err != nil {
		return 0, false, err
	}
	if resp == nil || len(resp.Kvs) == 0 || len(resp.Kvs[0].Value) == 0 {
		return 0, false, nil
	}
	idx, err := strconv.ParseUint(string(resp.Kvs[0].Value), 10, 64)
	if err != nil {
		return 0, false, err
	}
	return idx, true, nil
}

func assignV6Index(nsKey string) (uint64, error) {
	counterKey := v6IndexCounterKey()
	for i := 0; i < v6IndexMaxRetries; i++ {
		// Another writer may have just assigned this namespace.
		if idx, ok, err := readV6Index(nsKey); err != nil {
			return 0, err
		} else if ok {
			return idx, nil
		}

		// Reserve the next index by bumping the monotonic counter. The counter
		// is absent until first use; we never store 0, so cur==0 means absent.
		cur, _, err := readV6Index(counterKey)
		if err != nil {
			return 0, err
		}
		next := cur + 1
		if next > v6MaxIndex {
			return 0, ErrV6IndexExhausted
		}
		expected := ""
		if cur != 0 {
			expected = strconv.FormatUint(cur, 10)
		}
		ok, err := etcd.CompareAndSwapWithKey(counterKey, expected, strconv.FormatUint(next, 10))
		if err != nil {
			return 0, err
		}
		if !ok {
			// Lost the race for this counter value; retry with a fresh read.
			continue
		}

		// We own `next`. Bind it to the namespace if still unassigned.
		ok, err = etcd.CompareAndSwapWithKey(nsKey, "", strconv.FormatUint(next, 10))
		if err != nil {
			return 0, err
		}
		if ok {
			return next, nil
		}
		// The namespace was assigned concurrently; our reserved index becomes a
		// harmless gap. Return the value that won.
		if idx, found, err := readV6Index(nsKey); err != nil {
			return 0, err
		} else if found {
			return idx, nil
		}
	}
	return 0, fmt.Errorf("failed to allocate ipv6 namespace index after %d retries", v6IndexMaxRetries)
}

// v6PoolForIndex returns the /96 network, mask, gateway, and pool start/end for
// the given namespace index. The 48-bit index occupies the bytes above the /48
// prefix; the low 32 bits are the host range. The gateway is ::1 within the /96
// and the pool starts at ::2 to leave it out.
func v6PoolForIndex(index uint64) (network string, mask int32, gateway, poolStart, poolEnd string) {
	var base [16]byte
	copy(base[0:6], v6PrefixBytes[:])
	base[6] = byte(index >> 40)
	base[7] = byte(index >> 32)
	base[8] = byte(index >> 24)
	base[9] = byte(index >> 16)
	base[10] = byte(index >> 8)
	base[11] = byte(index)
	// bytes 12..15 (host) stay 0 for the network base.

	gw := base
	gw[15] = 1
	start := base
	start[15] = 2
	end := base
	end[12], end[13], end[14], end[15] = 0xff, 0xff, 0xff, 0xff

	return netip.AddrFrom16(base).String(), 96,
		netip.AddrFrom16(gw).String(),
		netip.AddrFrom16(start).String(),
		netip.AddrFrom16(end).String()
}
