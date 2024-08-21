/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
//nolint:lll // styles are too long and can not be split
package ibmvpc

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/models/pkg/netp"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func TestSGRule(t *testing.T) {
	sgJSON := `{
		"created_at": "2023-03-13T11:50:34Z",
		"crn": "olaa",
		"href": "href:9",
		"id": "id:10",
		"name": "sg1-ola",
		"resource_group": {
			"href": "href:6",
			"id": "id:7",
			"name": "anonymous"
		},
		"rules": [
			{
				"direction": "outbound",
				"href": "href:151",
				"id": "id:152",
				"ip_version": "ipv4",
				"protocol": "all",
				"local": {
					"cidr_block": "0.0.0.0/0"
				},
				"remote": {
					"cidr_block": "0.0.0.0/0"
				}
			},
			{
				"direction": "inbound",
				"href": "href:153",
				"id": "id:154",
				"ip_version": "ipv4",
				"protocol": "all",
				"local": {
					"address": "10.240.10.0"
				},
				"remote": {
					"cidr_block": "0.0.0.0/0"
				}
			}
		],
		"tags": [],
		"targets": [
			{
				"href": "href:86",
				"id": "id:87",
				"name": "contest-dance-divided-brilliant",
				"resource_type": "network_interface"
			},
			{
				"href": "href:70",
				"id": "id:71",
				"name": "data-washstand-blot-scrambler",
				"resource_type": "network_interface"
			}
		],
		"vpc": {
			"crn": "crn:12",
			"href": "href:13",
			"id": "id:14",
			"name": "test-vpc2-ky",
			"resource_type": "vpc"
		}
	}`

	sg := datamodel.SecurityGroup{}
	err := json.Unmarshal([]byte(sgJSON), &sg)
	require.Nil(t, err)
	sgResource := &commonvpc.SecurityGroup{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: *sg.Name,
			ResourceUID:  *sg.CRN,
			ResourceType: commonvpc.ResourceTypeSG,
			VPCRef:       nil,
			Region:       "",
		},
		Analyzer: commonvpc.NewSGAnalyzer(NewIBMSGAnalyzer(&sg.SecurityGroup)),
	}
	ruleStr, sgRule, _, err := sgResource.Analyzer.SgAnalyzer.GetSGRule(0)
	require.Nil(t, err)
	require.Equal(t, sgRule.Remote.Cidr.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.Local.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.Index, 0)
	require.Equal(t, ruleStr, "direction: outbound,  conns: protocol: all, remote: 0.0.0.0/0, local: 0.0.0.0/0, id: id:152\n")
	ruleStr, sgRule, _, err = sgResource.Analyzer.SgAnalyzer.GetSGRule(1)
	require.Nil(t, err)
	require.Equal(t, sgRule.Remote.Cidr.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.Local.String(), "10.240.10.0")
	require.Equal(t, sgRule.Index, 1)
	require.Equal(t, ruleStr, "direction: inbound,  conns: protocol: all, remote: 0.0.0.0/0, local: 10.240.10.0/32, id: id:154\n")
}

type sgTest struct {
	name                    string
	rules                   []*commonvpc.SGRule
	isIngress               bool
	expectedConnectivityMap commonvpc.ConnectivityResultMap
}

func fromIPRangeStrWithoutValidation(ipRange string) *ipblock.IPBlock {
	ip, _ := ipblock.FromIPRangeStr(ipRange)
	return ip
}

func fromIPAddressStrWithoutValidation(ipAddress string) *ipblock.IPBlock {
	ip, _ := ipblock.FromIPAddress(ipAddress)
	return ip
}

var sgTests = []sgTest{
	{
		name: "local_field_is_all_ip_range", // (local as 0.0.0.0/0 is default for old config with local field not enabled)
		rules: []*commonvpc.SGRule{
			{
				Remote:      commonvpc.NewRuleTarget(newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.1"), "ola"),
				Connections: connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245),
				Index:       1,
				Local:       ipblock.GetCidrAll(),
			},
			{
				Remote:      commonvpc.NewRuleTarget(newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.0/30"), "ola"),
				Connections: connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
				Index:       2,
				Local:       ipblock.GetCidrAll(),
			},
		},
		isIngress: false,
		expectedConnectivityMap: map[*ipblock.IPBlock]*commonvpc.ConnectivityResult{
			ipblock.GetCidrAll(): {
				IsIngress: false,
				AllowedConns: map[*ipblock.IPBlock]*connection.Set{
					fromIPAddressStrWithoutValidation("10.250.10.0"):               connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("10.250.10.2-10.250.10.3"):     connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        connection.None(),
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): connection.None(),
					fromIPAddressStrWithoutValidation("10.250.10.1"):               connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000).Union(connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245)),
				},
				AllowRules: map[*ipblock.IPBlock][]int{
					fromIPAddressStrWithoutValidation("10.250.10.0"):               {2},
					fromIPRangeStrWithoutValidation("10.250.10.2-10.250.10.3"):     {2},
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        {},
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): {},
					fromIPAddressStrWithoutValidation("10.250.10.1"):               {1, 2},
				},
				DeniedConns: map[*ipblock.IPBlock]*connection.Set{},
				DenyRules:   map[*ipblock.IPBlock][]int{},
			},
		},
	},
	{
		name: "local_field_in_rules_is_not_all_range", // a more interesting case of local field with effect on connectivity
		rules: []*commonvpc.SGRule{
			{
				Remote:      commonvpc.NewRuleTarget(newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.1"), "ola"),
				Connections: connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245),
				Index:       1,
				Local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.1"),
			},
			{
				Remote:      commonvpc.NewRuleTarget(newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.0/30"), "ola"),
				Connections: connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
				Index:       2,
				Local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.0/30"),
			},
		},
		isIngress: false,
		expectedConnectivityMap: map[*ipblock.IPBlock]*commonvpc.ConnectivityResult{
			fromIPAddressStrWithoutValidation("10.240.10.1"): {
				IsIngress: false,
				AllowedConns: map[*ipblock.IPBlock]*connection.Set{
					fromIPAddressStrWithoutValidation("10.250.10.0"):               connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("10.250.10.2-10.250.10.3"):     connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        connection.None(),
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): connection.None(),
					fromIPAddressStrWithoutValidation("10.250.10.1"): connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000).Union(
						connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245)),
				},
				AllowRules: map[*ipblock.IPBlock][]int{
					fromIPAddressStrWithoutValidation("10.250.10.0"):               {2},
					fromIPRangeStrWithoutValidation("10.250.10.2-10.250.10.3"):     {2},
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        {},
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): {},
					fromIPAddressStrWithoutValidation("10.250.10.1"):               {1, 2},
				},
				DeniedConns: map[*ipblock.IPBlock]*connection.Set{},
				DenyRules:   map[*ipblock.IPBlock][]int{},
			},
			fromIPAddressStrWithoutValidation("10.240.10.0"): {
				IsIngress: false,
				AllowedConns: map[*ipblock.IPBlock]*connection.Set{
					fromIPRangeStrWithoutValidation("10.250.10.0-10.250.10.3"):     connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        connection.None(),
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): connection.None(),
				},
				AllowRules: map[*ipblock.IPBlock][]int{
					fromIPRangeStrWithoutValidation("10.250.10.0-10.250.10.3"):     {2},
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        {},
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): {},
				},
				DeniedConns: map[*ipblock.IPBlock]*connection.Set{},
				DenyRules:   map[*ipblock.IPBlock][]int{},
			},
			fromIPRangeStrWithoutValidation("10.240.10.2-10.240.10.3"): {
				IsIngress: false,
				AllowedConns: map[*ipblock.IPBlock]*connection.Set{
					fromIPRangeStrWithoutValidation("10.250.10.0-10.250.10.3"):     connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        connection.None(),
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): connection.None(),
				},
				AllowRules: map[*ipblock.IPBlock][]int{
					fromIPRangeStrWithoutValidation("10.250.10.0-10.250.10.3"):     {2},
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        {},
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): {},
				},
				DeniedConns: map[*ipblock.IPBlock]*connection.Set{},
				DenyRules:   map[*ipblock.IPBlock][]int{},
			},
		},
	},
}

func (tt *sgTest) runTest(t *testing.T) {
	var endpoint1 = &commonvpc.NetworkInterface{InternalNode: vpcmodel.InternalNode{
		AddressStr: "10.240.10.1",
		IPBlockObj: fromIPAddressStrWithoutValidation("10.240.10.1"),
	}}
	var endpoint2 = &commonvpc.NetworkInterface{InternalNode: vpcmodel.InternalNode{
		AddressStr: "10.240.10.2",
		IPBlockObj: fromIPAddressStrWithoutValidation("10.240.10.2"),
	}}
	var endpoint3 = &commonvpc.NetworkInterface{InternalNode: vpcmodel.InternalNode{
		AddressStr: "10.240.10.0",
		IPBlockObj: fromIPAddressStrWithoutValidation("10.240.10.0"),
	}}

	sg := commonvpc.SecurityGroup{Members: map[string]vpcmodel.Node{"10.240.10.1": endpoint1, "10.240.10.2": endpoint2, "10.240.10.0": endpoint3}}
	connectivityMap := commonvpc.MapAndAnalyzeSGRules(tt.rules, false, &sg)
	require.True(t, connectivityMap.Equal(tt.expectedConnectivityMap))
}

func TestMapAndAnalyzeSGRules(t *testing.T) {
	for testIdx := range sgTests {
		tt := sgTests[testIdx]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTest(t)
		})
	}
	fmt.Println("done")
}

func TestCaching(t *testing.T) {
	// test to check caching in mapAndAnalyzeSGRules
	c1 := connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245)
	c2 := connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000)
	var endpoint1 = &commonvpc.NetworkInterface{InternalNode: vpcmodel.InternalNode{
		AddressStr: "10.240.10.1",
		IPBlockObj: fromIPAddressStrWithoutValidation("10.240.10.1"),
	}}

	sg := commonvpc.SecurityGroup{Members: map[string]vpcmodel.Node{"10.240.10.1": endpoint1}}

	rulesTest1 := []*commonvpc.SGRule{
		{
			Remote:      commonvpc.NewRuleTarget(newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.1"), "ola"),
			Connections: c1,
			Index:       1,
			Local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.1"),
		},
		{
			Remote:      commonvpc.NewRuleTarget(newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.0/30"), "ola"),
			Connections: c2,
			Index:       2,
			Local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.0/30"),
		},
	}

	egressConnectivityMap := commonvpc.MapAndAnalyzeSGRules(rulesTest1, false, &sg)

	// in this example we should get the same ConnectivityResult for both IPBlock 10.240.10.0 and 10.240.10.2-10.240.10.3
	var connectivityResult1, connectivityResult2 *commonvpc.ConnectivityResult
	for local, connectivityResult := range egressConnectivityMap {
		if local.Equal(newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.0")) {
			connectivityResult1 = connectivityResult
		}
		if local.Equal(newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.2/31")) {
			connectivityResult2 = connectivityResult
		}
	}
	require.True(t, connectivityResult1 == connectivityResult2) // compare pointers-- to make sure that caching worked
}

func newIPBlockFromCIDROrAddressWithoutValidation(cidr string) *ipblock.IPBlock {
	res, _ := ipblock.FromCidrOrAddress(cidr)
	return res
}
