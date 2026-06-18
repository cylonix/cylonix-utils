// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipdrawer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	ipd "github.com/cylonix/ipdrawer"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/optional"
)

type IPDrawerInterface interface {
	AllocateIPAddr(namespace, popName, uuid string, want *netip.Addr) (string, error)
	AllocateIPv6Addr(namespace, popName, uuid string, want *netip.Addr) (string, error)
	ReleaseIPAddr(namespace, popName, ip string) error
	InitIPdrawer() error
}

var (
	ipDrawerInstance          IPDrawerInterface
	ErrIPDrawerNotProvisioned = errors.New("ip drawer service not provisioned")
	ErrIPDrawerClientNotReady = errors.New("ip drawer client is not ready")

	// From Tailscale CGNAT range definitions:
	// https://github.com/tailscale/tailscale/blob/main/net/tsaddr/tsaddr.go
	// ChromeOSVMRange is the subset of the CGNAT IPv4 range used by
	// ChromeOS to interconnect the host OS to containers and VMs. We
	// avoid allocating IPs from it, to avoid conflicts.
	chromeOSVMRange = "100.115.92.0/23"
)

// Private address ranges that node addresses are drawn from. IPv4 uses the
// Tailscale CGNAT range 100.64.0.0/10; IPv6 uses the Tailscale ULA range
// fd7a:115c:a1e0::/48 (the v6 analog of the CGNAT range). A pool in ipdrawer is
// single-family, determined by its start/end addresses, so v4 and v6 live in two
// distinct networks/pools under the same namespace.
const (
	v4Network   = "100.64.0.0"
	v4Mask      = 10
	v4Gateway   = "100.64.0.1"
	v4PoolStart = "100.64.1.1"
	v4PoolEnd   = "100.98.255.255"
)

// The v6 network/pool is per-namespace and globally unique; see v6index.go.

// poolInfo describes the ipdrawer network/pool to allocate a node address from.
type poolInfo struct {
	network   string
	mask      int32
	gateway   string
	poolStart string
	poolEnd   string
	exclude   string // CIDR to exclude from allocation; empty if none.
	tagKey    string
	tagValue  string
}

type IPDrawer struct {
	client *ipd.APIClient
}

func NewIPDrawer(serverURL string) (*IPDrawer, error) {
	var (
		err    error
		schema string
		server string
		port   int
	)
	if serverURL != "" {
		schema, server, port, err = utils.ParseServerURL(serverURL)
	} else {
		schema, server, port, err = utils.GetIPDrawerConfig()
		serverURL = fmt.Sprintf("%s://%s:%d", schema, server, port)
	}
	if err != nil {
		return nil, err
	}
	return &IPDrawer{
		client: ipd.NewAPIClient(&ipd.Configuration{
			Host:       fmt.Sprintf("%s:%d", server, port),
			Scheme:     schema,
			HTTPClient: &http.Client{},
			Servers: []ipd.ServerConfiguration{
				{
					URL:         serverURL,
					Description: "ip drawer server",
				},
			},
		}),
	}, nil
}
func SetIPDrawerImpl(ipDrawer IPDrawerInterface) {
	ipDrawerInstance = ipDrawer
}
func InitIPdrawer(serverURL string) error {
	IPDrawerImpl, e := NewIPDrawer(serverURL)
	if e != nil {
		return e
	}
	e = IPDrawerImpl.InitIPdrawer()
	if e != nil {
		return e
	}
	SetIPDrawerImpl(IPDrawerImpl)
	return nil
}
func AllocateIPAddr(namespace, popName, uuid string, wantIP *netip.Addr) (string, error) {
	if ipDrawerInstance != nil {
		return ipDrawerInstance.AllocateIPAddr(namespace, popName, uuid, wantIP)
	}
	return "", ErrIPDrawerNotProvisioned

}
func AllocateIPv6Addr(namespace, popName, uuid string, wantIP *netip.Addr) (string, error) {
	if ipDrawerInstance != nil {
		return ipDrawerInstance.AllocateIPv6Addr(namespace, popName, uuid, wantIP)
	}
	return "", ErrIPDrawerNotProvisioned
}
func ReleaseIPAddr(namespace, popName, ip string) error {
	if ipDrawerInstance != nil {
		return ipDrawerInstance.ReleaseIPAddr(namespace, popName, ip)
	}
	return ErrIPDrawerNotProvisioned
}

// TODO: This should be part of namespace per wg configuration
func getIPdrawerPoolInfo(namespace, _ string, isV6 bool) (poolInfo, error) {
	if isV6 {
		index, err := namespaceV6Index(namespace)
		if err != nil {
			return poolInfo{}, err
		}
		network, mask, gateway, poolStart, poolEnd := v6PoolForIndex(index)
		return poolInfo{
			network:   network,
			mask:      mask,
			gateway:   gateway,
			poolStart: poolStart,
			poolEnd:   poolEnd,
			exclude:   "", // No v6 analog of the ChromeOS VM range.
			tagKey:    "namespace",
			tagValue:  namespace,
		}, nil
	}
	return poolInfo{
		network:   v4Network,
		mask:      v4Mask,
		gateway:   v4Gateway,
		poolStart: v4PoolStart,
		poolEnd:   v4PoolEnd,
		exclude:   chromeOSVMRange,
		tagKey:    "namespace",
		tagValue:  namespace,
	}, nil
}

// samePrefix reports whether two CIDR strings denote the same network,
// tolerating differing-but-equivalent IPv6 text forms. Falls back to string
// comparison if either side does not parse as a prefix.
func samePrefix(a, b string) bool {
	pa, ea := netip.ParsePrefix(a)
	pb, eb := netip.ParsePrefix(b)
	if ea == nil && eb == nil {
		return pa.Masked() == pb.Masked()
	}
	return a == b
}

func (ipDrawer *IPDrawer) InitIPdrawer() error {
	return nil
}

func (ipDrawer *IPDrawer) checkAndCreateNamespaceNetwork(namespace string, info poolInfo) error {
	ctx := context.Background()
	if ipDrawer.client == nil {
		return ErrIPDrawerClientNotReady
	}
	ret, rsp, err := ipDrawer.client.NetworkServiceV0API.NetworkServiceV0ListNetwork(ctx, namespace).Execute()
	if err != nil {
		v := ""
		if rsp.Body != nil {
			buf := make([]byte, 1024)
			n, _ := rsp.Body.Read(buf)
			if n > 0 {
				buf = buf[:n]
				v = string(buf)
			}
		}
		return fmt.Errorf("failed to list network: code=%v('%v') %w", rsp.StatusCode, v, err)
	}
	// A namespace can hold both a v4 and a v6 network, so check for the
	// specific (network, mask) rather than "any network exists".
	wantPrefix := fmt.Sprintf("%s/%d", info.network, info.mask)
	networkExists := false
	if ret != nil {
		for _, n := range ret.Networks {
			if samePrefix(optional.V(n.Prefix, ""), wantPrefix) {
				networkExists = true
				break
			}
		}
	}
	if !networkExists {
		gateways := []string{info.gateway}
		v, rsp, err := ipDrawer.client.NetworkServiceV0API.NetworkServiceV0CreateNetwork(
			ctx,
			namespace,
			info.network,
			info.mask,
		).Body(
			ipd.NetworkServiceV0CreateNetworkBody{
				DefaultGateways: gateways,
				Status:          optional.P(ipd.ModelNetworkStatus_1),
				Tags: []ipd.ModelTag{
					{
						Key: optional.P("namespace"), Value: &namespace,
					},
				},
			}).Execute()
		if err != nil {
			return fmt.Errorf("failed to create network: code=%v(%v) %w", rsp.StatusCode, v, err)
		}
		// On success, ipdrawer returns `200 {}` which the openapi-generated
		// client unmarshals to a non-nil empty map[string]interface{}. The
		// original `v != nil` check fired on every success; only treat a
		// non-empty body as the error case (older ipdrawer responses
		// included a status/message field).
		if len(v) > 0 {
			return fmt.Errorf("failed to create network: message=%v", v)
		}
	}
	ret2, rsp, err := ipDrawer.client.NetworkServiceV0API.
		NetworkServiceV0GetPoolsInNetwork(ctx, namespace, info.network, info.mask).
		Execute()
	if err != nil {
		v := ""
		if rsp.Body != nil {
			buf := make([]byte, 1024)
			n, _ := rsp.Body.Read(buf)
			if n > 0 {
				buf = buf[:n]
				v = string(buf)
			}
		}
		return fmt.Errorf("failed to list network pool: code=%v('%v') %w", rsp.StatusCode, v, err)
	}
	if ret2 == nil || len(ret2.Pools) <= 0 {
		v, rsp, err := ipDrawer.client.NetworkServiceV0API.NetworkServiceV0CreatePool(
			ctx,
			namespace,
			info.network,
			info.mask,
		).Body(ipd.NetworkServiceV0CreatePoolBody{
			Pool: &ipd.ModelPool{
				Start:     optional.P(info.poolStart),
				End:       optional.P(info.poolEnd),
				Namespace: &namespace,
				Status:    optional.P(ipd.ModelPoolStatus_1),
				Tags: []ipd.ModelTag{
					{
						Key: optional.P("namespace"), Value: &namespace,
					},
				},
			},
		},
		).Execute()
		if err != nil {
			return fmt.Errorf("failed to create pool: code=%v %w", rsp.StatusCode, err)
		}
		// See comment on CreateNetwork above — empty map = success.
		if len(v) > 0 {
			return fmt.Errorf("failed to create pool: message=%v", v)
		}
	}
	return nil
}

func (ipDrawer *IPDrawer) AllocateIPAddr(namespace, popName, uuid string, want *netip.Addr) (string, error) {
	return ipDrawer.allocate(namespace, popName, uuid, want, false)
}

func (ipDrawer *IPDrawer) AllocateIPv6Addr(namespace, popName, uuid string, want *netip.Addr) (string, error) {
	return ipDrawer.allocate(namespace, popName, uuid, want, true)
}

func (ipDrawer *IPDrawer) allocate(namespace, popName, uuid string, want *netip.Addr, isV6 bool) (string, error) {
	info, err := getIPdrawerPoolInfo(namespace, popName, isV6)
	if err != nil {
		return "", err
	}
	if ipDrawer.client == nil {
		return "", ErrIPDrawerClientNotReady
	}
	ctx := context.Background()
	ip := info.network
	if want != nil {
		ip = want.String()
	}
	if err := ipDrawer.checkAndCreateNamespaceNetwork(namespace, info); err != nil {
		return "", err
	}
	body := ipd.NetworkServiceV0DrawIPBody{
		IP:                &ip,
		Mask:              &info.mask,
		TemporaryReserved: optional.P(false),
		UUID:              &uuid,
		PoolTag: &ipd.ModelTag{
			Key:   &info.tagKey,
			Value: &info.tagValue,
		},
		MustHaveWantIP: optional.P(want != nil),
	}
	if info.exclude != "" {
		body.Exclude = &info.exclude
	}
	ret, rsp, err := ipDrawer.client.NetworkServiceV0API.NetworkServiceV0DrawIP(
		ctx, namespace, ip, info.mask).Body(body).Execute()
	if err != nil {
		return "", fmt.Errorf("failed to draw ip: code=%v err=%w", rsp.StatusCode, err)
	}
	if ret.IP == nil {
		return "", fmt.Errorf("failed to draw ip: code=%v err=%v", rsp.StatusCode, optional.V(ret.Message, ""))
	}
	return *ret.IP, err
}

func (ipDrawer *IPDrawer) ReleaseIPAddr(namespace, popName, ip string) error {
	ctx := context.Background()
	if ipDrawer.client == nil {
		return ErrIPDrawerClientNotReady
	}
	_, rsp, err := ipDrawer.client.IPServiceV0API.IPServiceV0DeactivateIP(ctx, namespace, ip).Execute()
	if err != nil {
		err = fmt.Errorf("failed to release ip: code=%v %w", rsp.StatusCode, err)
	}
	return err
}
