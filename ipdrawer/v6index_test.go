// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipdrawer

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/cylonix/utils/etcd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestV6PoolForIndex(t *testing.T) {
	tests := []struct {
		index       uint64
		wantNetwork string
		wantGateway string
		wantStart   string
		wantEnd     string
	}{
		{
			index:       1,
			wantNetwork: "fd7a:115c:a1e0:0:0:1::",
			wantGateway: "fd7a:115c:a1e0:0:0:1::1",
			wantStart:   "fd7a:115c:a1e0:0:0:1::2",
			wantEnd:     "fd7a:115c:a1e0:0:0:1:ffff:ffff",
		},
		{
			index:       2,
			wantNetwork: "fd7a:115c:a1e0:0:0:2::",
			wantStart:   "fd7a:115c:a1e0:0:0:2::2",
		},
	}
	for _, tc := range tests {
		network, mask, gateway, start, end := v6PoolForIndex(tc.index)
		assert.EqualValues(t, 96, mask)

		// Compare as parsed addresses so canonical text differences don't matter.
		assert.Equal(t, netip.MustParseAddr(tc.wantNetwork), netip.MustParseAddr(network), "network idx=%d", tc.index)
		assert.Equal(t, netip.MustParseAddr(tc.wantStart), netip.MustParseAddr(start), "start idx=%d", tc.index)
		if tc.wantGateway != "" {
			assert.Equal(t, netip.MustParseAddr(tc.wantGateway), netip.MustParseAddr(gateway), "gateway idx=%d", tc.index)
		}
		if tc.wantEnd != "" {
			assert.Equal(t, netip.MustParseAddr(tc.wantEnd), netip.MustParseAddr(end), "end idx=%d", tc.index)
		}

		// The pool is the low 32 bits of the /96, well within 2^32 so ipdrawer
		// can allocate randomly. Verify start/end share the /96 network.
		netPrefix := netip.MustParsePrefix(network + "/96")
		assert.True(t, netPrefix.Contains(netip.MustParseAddr(start)), "start in /96 idx=%d", tc.index)
		assert.True(t, netPrefix.Contains(netip.MustParseAddr(end)), "end in /96 idx=%d", tc.index)
	}

	// Distinct indices must map to distinct, non-overlapping networks.
	n1, _, _, _, _ := v6PoolForIndex(1)
	n2, _, _, _, _ := v6PoolForIndex(2)
	assert.NotEqual(t, n1, n2)
}

func TestNamespaceV6IndexAllocation(t *testing.T) {
	em, err := etcd.NewEmulator()
	require.NoError(t, err)
	etcd.SetImpl(em)
	defer etcd.SetImpl(nil)
	v6IndexCache = sync.Map{}

	// First namespace gets index 1, second gets 2.
	idxA, err := namespaceV6Index("ns-a")
	require.NoError(t, err)
	assert.EqualValues(t, 1, idxA)

	idxB, err := namespaceV6Index("ns-b")
	require.NoError(t, err)
	assert.EqualValues(t, 2, idxB)

	// Stable: same namespace returns the same index (from cache and from etcd).
	again, err := namespaceV6Index("ns-a")
	require.NoError(t, err)
	assert.EqualValues(t, 1, again)

	v6IndexCache = sync.Map{} // drop cache, force re-read from etcd
	fromEtcd, err := namespaceV6Index("ns-a")
	require.NoError(t, err)
	assert.EqualValues(t, 1, fromEtcd, "index must be stable across cache eviction")

	// Distinct namespaces never collide.
	assert.NotEqual(t, idxA, idxB)
}
