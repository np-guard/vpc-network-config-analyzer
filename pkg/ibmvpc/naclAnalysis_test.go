/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc/testfunc"
)

func TestGetRules(t *testing.T) {
	rc := NewIBMresourcesContainer()
	err := rc.ParseResourcesFromFile(filepath.Join(testfunc.GetTestsDirInput(), "input_acl_testing3.json"))
	require.Nilf(t, err, "err: %s", err)
	vpcConfigs, err := rc.VPCConfigsFromResources("", nil, nil)
	require.Nilf(t, err, "err: %s", err)
	for _, config := range vpcConfigs.Configs() {
		for _, f := range config.FilterResources {
			if naclLayer, ok := f.(*commonvpc.NaclLayer); ok {
				for _, nacl := range naclLayer.NaclList {
					testSingleNACL(nacl)
				}
			}
		}
	}
}

func testSingleNACL(nacl *commonvpc.NACL) {
	// test addAnalysisPerSubnet
	for _, subnet := range nacl.Subnets {
		nacl.Analyzer.AddAnalysisPerSubnet(subnet)
		// functions to test
		// AnalyzeNACLRulesPerDisjointTargets
		// getAllowedXgressConnections
	}
}

func TestGetAllowedXgressConnections(t *testing.T) {
	subnet := newIPBlockFromCIDROrAddressWithoutValidation("10.0.0.0/24")

	tests := []struct {
		testName                string
		naclRules               []*commonvpc.NACLRule
		expectedConnectivityMap map[string]*commonvpc.ConnectivityResult
	}{
		{

			testName: "a",
			naclRules: []*commonvpc.NACLRule{
				{
					Src:         newIPBlockFromCIDROrAddressWithoutValidation("1.2.3.4/32"),
					Dst:         newIPBlockFromCIDROrAddressWithoutValidation("10.0.0.1/32"),
					Connections: netset.AllTransports(),
					Action:      "deny",
				},
				{
					Src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
					Dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
					Connections: netset.AllTransports(),
					Action:      "allow",
				},
			},
			expectedConnectivityMap: map[string]*commonvpc.ConnectivityResult{
				"10.0.0.0-10.0.0.0": {
					IsIngress: true,
					AllowedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         netset.AllTransports(),
					},
					AllowRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {0},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {0},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {0},
					},
					DeniedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         netset.NoTransports(),
					},
					DenyRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {},
					},
				},
				"10.0.0.1-10.0.0.1": {
					IsIngress: true,
					AllowedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         netset.NoTransports(),
					},
					AllowRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {0},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {0},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {},
					},
					DeniedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         netset.AllTransports(),
					},
					DenyRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {0},
					},
				},
				"10.0.0.2-10.0.0.255": {
					IsIngress: true,
					AllowedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         netset.AllTransports(),
					},
					AllowRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {0},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {0},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {0},
					},
					DeniedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         netset.NoTransports(),
					},
					DenyRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {},
					},
				},
			},
		},
		{
			testName: "b",
			naclRules: []*commonvpc.NACLRule{
				{
					Src:         newIPBlockFromCIDROrAddressWithoutValidation("1.2.3.4/32"),
					Dst:         newIPBlockFromCIDROrAddressWithoutValidation("10.0.0.1/32"),
					Connections: netset.NewTCPTransport(80, 80, netp.MinPort, netp.MaxPort),
					Action:      "allow",
				},
				{
					Src:         newIPBlockFromCIDROrAddressWithoutValidation("1.2.3.4/32"),
					Dst:         newIPBlockFromCIDROrAddressWithoutValidation("10.0.0.1/32"),
					Connections: netset.NewTCPTransport(1, 100, netp.MinPort, netp.MaxPort),
					Action:      "deny",
				},
				{
					Src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
					Dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
					Connections: netset.AllTransports(),
					Action:      "allow",
				},
			},
			expectedConnectivityMap: map[string]*commonvpc.ConnectivityResult{
				"10.0.0.0-10.0.0.0": {
					IsIngress: true,
					AllowedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         netset.AllTransports(),
					},
					AllowRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {0},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {0},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {0},
					},
					DeniedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         netset.NoTransports(),
					},
					DenyRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {},
					},
				},
				"10.0.0.1-10.0.0.1": {
					IsIngress: true,
					AllowedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"): netset.NewTCPorUDPTransport(
							netp.ProtocolString("TCP"), 80, 80, netp.MinPort, netp.MaxPort).Union(
							netset.NewTCPorUDPTransport(netp.ProtocolString("TCP"), 101, 65535, netp.MinPort, netp.MaxPort).Union(
								netset.AllICMPTransport().Union(netset.AllUDPTransport()),
							),
						),
					},
					AllowRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {0},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {0},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {0, 0},
					},
					DeniedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"): netset.NewTCPorUDPTransport(
							netp.ProtocolString("TCP"), 1, 79, netp.MinPort, netp.MaxPort).Union(
							netset.NewTCPorUDPTransport(netp.ProtocolString("TCP"), 81, 100, netp.MinPort, netp.MaxPort),
						),
					},
					DenyRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {0},
					},
				},
				"10.0.0.2-10.0.0.255": {
					IsIngress: true,
					AllowedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.AllTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         netset.AllTransports(),
					},
					AllowRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {0},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {0},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {0},
					},
					DeniedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): netset.NoTransports(),
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         netset.NoTransports(),
					},
					DenyRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-1.2.3.3"):         {},
						fromIPRangeStrWithoutValidation("1.2.3.5-255.255.255.255"): {},
						fromIPRangeStrWithoutValidation("1.2.3.4-1.2.3.4"):         {},
					},
				},
			},
		},
		{
			testName: "c",
			naclRules: []*commonvpc.NACLRule{
				{
					Dst:         newIPBlockFromCIDROrAddressWithoutValidation("1.2.3.4/32"),
					Src:         newIPBlockFromCIDROrAddressWithoutValidation("10.0.0.1/32"),
					Connections: netset.AllTransports(),
					Action:      "deny",
				},
				{
					Dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
					Src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
					Connections: netset.AllTransports(),
					Action:      "allow",
				},
			},
			expectedConnectivityMap: map[string]*commonvpc.ConnectivityResult{
				"10.0.0.0-10.0.0.255": {
					IsIngress: true,
					AllowedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-10.0.0.0"):         netset.AllTransports(),
						fromIPRangeStrWithoutValidation("10.0.0.1-10.0.0.1"):        netset.AllTransports(),
						fromIPRangeStrWithoutValidation("10.0.0.2-255.255.255.255"): netset.AllTransports(),
					},
					AllowRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-10.0.0.0"):         {0},
						fromIPRangeStrWithoutValidation("10.0.0.1-10.0.0.1"):        {},
						fromIPRangeStrWithoutValidation("10.0.0.2-255.255.255.255"): {0},
					},
					DeniedConns: map[*netset.IPBlock]*netset.TransportSet{
						fromIPRangeStrWithoutValidation("0.0.0.0-10.0.0.0"):         netset.NoTransports(),
						fromIPRangeStrWithoutValidation("10.0.0.1-10.0.0.1"):        netset.NoTransports(),
						fromIPRangeStrWithoutValidation("10.0.0.2-255.255.255.255"): netset.NoTransports(),
					},
					DenyRules: map[*netset.IPBlock][]int{
						fromIPRangeStrWithoutValidation("0.0.0.0-10.0.0.0"):         {},
						fromIPRangeStrWithoutValidation("10.0.0.1-10.0.0.1"):        {},
						fromIPRangeStrWithoutValidation("10.0.0.2-255.255.255.255"): {},
					},
				},
			},
		},
	}

	for _, test := range tests {
		connectivityMap := commonvpc.AnalyzeNACLRulesPerDisjointTargets(test.naclRules, subnet, true)
		require.True(t, equalConnectivityMap(connectivityMap, test.expectedConnectivityMap))
	}
	fmt.Printf("done\n")
}

func storeAndSortKeys[T any](m map[string]*commonvpc.ConnectivityResult) []string {
	keys := make([]string, len(m))
	i := 0
	for ipBlockString := range m {
		keys[i] = ipBlockString
		i += 1
	}
	sort.Strings(keys)
	return keys
}

func equalKeys(first, second map[string]*commonvpc.ConnectivityResult) bool {
	if len(first) != len(second) {
		return false
	}
	keys1 := slices.Collect(maps.Keys(first))
	sort.Strings(keys1)
	keys2 := slices.Collect(maps.Keys(second))
	sort.Strings(keys2)
	// compare the concatenation result to validate equality of keys sets
	return reflect.DeepEqual(keys1, keys2)
}

func equalConnectivityMap(connectivityMap, other map[string]*commonvpc.ConnectivityResult) bool {
	if !equalKeys(connectivityMap, other) {
		return false
	}
	for ipBlockString, connectivityResult := range connectivityMap {
		fmt.Printf("ipBlockString: %v\n", ipBlockString)
		fmt.Printf("connectivityResult.AllowedConns: \n")
		for ipRange, conn := range connectivityResult.AllowedConns {
			fmt.Printf("ipRange.ToIPRanges(): %v\n", ipRange.ToIPRanges())
			fmt.Printf("conn: %v\n", conn)
		}

		fmt.Printf("connectivityResult.AllowRules: \n")
		for ipRange, conn := range connectivityResult.AllowRules {
			fmt.Printf("ipRange.ToIPRanges(): %v\n", ipRange.ToIPRanges())
			fmt.Printf("conn: %v\n", conn)
		}
		fmt.Printf("connectivityResult.DeniedConns: \n")
		for ipRange, conn := range connectivityResult.DeniedConns {
			fmt.Printf("ipRange.ToIPRanges(): %v\n", ipRange.ToIPRanges())
			fmt.Printf("conn: %v\n", conn)
		}

		fmt.Printf("connectivityResult.DenyRules: \n")
		for ipRange, conn := range connectivityResult.DenyRules {
			fmt.Printf("ipRange.ToIPRanges(): %v\n", ipRange.ToIPRanges())
			fmt.Printf("conn: %v\n", conn)
		}
		for otherIPBlockString, expectedConnectivityResult := range other {
			if ipBlockString == otherIPBlockString {
				if !connectivityResult.Equal(expectedConnectivityResult) {
					return false
				}
				break
			}
		}
	}
	return true
}
