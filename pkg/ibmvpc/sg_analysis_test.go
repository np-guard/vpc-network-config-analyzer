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
	sgResource := &SecurityGroup{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: *sg.Name,
			ResourceUID:  *sg.CRN,
			ResourceType: ResourceTypeSG,
			VPCRef:       nil,
			Region:       "",
		},
		analyzer: NewSGAnalyzer(&sg.SecurityGroup),
	}
	ruleStr, sgRule, _, err := sgResource.analyzer.getSGRule(0)
	require.Nil(t, err)
	require.Equal(t, sgRule.remote.cidr.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.local.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.index, 0)
	require.Equal(t, ruleStr, "index: 0, direction: outbound,  conns: protocol: all, remote: 0.0.0.0/0, local: 0.0.0.0/0\n")
	ruleStr, sgRule, _, err = sgResource.analyzer.getSGRule(1)
	require.Nil(t, err)
	require.Equal(t, sgRule.remote.cidr.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.local.String(), "10.240.10.0")
	require.Equal(t, sgRule.index, 1)
	require.Equal(t, ruleStr, "index: 1, direction: inbound,  conns: protocol: all, remote: 0.0.0.0/0, local: 10.240.10.0/32\n")
}

type sgTest struct {
	name                    string
	rules                   []*SGRule
	isIngress               bool
	expectedConnectivityMap ConnectivityResultMap
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
		rules: []*SGRule{
			{
				remote:      ruleTarget{sgName: "ola", cidr: newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.1")},
				connections: connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245),
				index:       1,
				local:       ipblock.GetCidrAll(),
			},
			{
				remote:      ruleTarget{sgName: "ola", cidr: newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.0/30")},
				connections: connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
				index:       2,
				local:       ipblock.GetCidrAll(),
			},
		},
		isIngress: false,
		expectedConnectivityMap: map[*ipblock.IPBlock]*ConnectivityResult{
			ipblock.GetCidrAll(): {
				isIngress: false,
				allowedConns: map[*ipblock.IPBlock]*connection.Set{
					fromIPAddressStrWithoutValidation("10.250.10.0"):               connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("10.250.10.2-10.250.10.3"):     connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        connection.None(),
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): connection.None(),
					fromIPAddressStrWithoutValidation("10.250.10.1"):               connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000).Union(connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245)),
				},
				allowRules: map[*ipblock.IPBlock][]int{
					fromIPAddressStrWithoutValidation("10.250.10.0"):               {2},
					fromIPRangeStrWithoutValidation("10.250.10.2-10.250.10.3"):     {2},
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        {},
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): {},
					fromIPAddressStrWithoutValidation("10.250.10.1"):               {1, 2},
				},
				deniedConns: map[*ipblock.IPBlock]*connection.Set{},
				denyRules:   map[*ipblock.IPBlock][]int{},
			},
		},
	},
	{
		name: "local_field_in_rules_is_not_all_range", // a more interesting case of local field with effect on connectivity
		rules: []*SGRule{
			{
				remote:      ruleTarget{sgName: "ola", cidr: newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.1")},
				connections: connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245),
				index:       1,
				local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.1"),
			},
			{
				remote:      ruleTarget{sgName: "ola", cidr: newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.0/30")},
				connections: connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
				index:       2,
				local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.0/30"),
			},
		},
		isIngress: false,
		expectedConnectivityMap: map[*ipblock.IPBlock]*ConnectivityResult{
			fromIPAddressStrWithoutValidation("10.240.10.1"): {
				isIngress: false,
				allowedConns: map[*ipblock.IPBlock]*connection.Set{
					fromIPAddressStrWithoutValidation("10.250.10.0"):               connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("10.250.10.2-10.250.10.3"):     connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        connection.None(),
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): connection.None(),
					fromIPAddressStrWithoutValidation("10.250.10.1"): connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000).Union(
						connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245)),
				},
				allowRules: map[*ipblock.IPBlock][]int{
					fromIPAddressStrWithoutValidation("10.250.10.0"):               {2},
					fromIPRangeStrWithoutValidation("10.250.10.2-10.250.10.3"):     {2},
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        {},
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): {},
					fromIPAddressStrWithoutValidation("10.250.10.1"):               {1, 2},
				},
				deniedConns: map[*ipblock.IPBlock]*connection.Set{},
				denyRules:   map[*ipblock.IPBlock][]int{},
			},
			fromIPAddressStrWithoutValidation("10.240.10.0"): {
				isIngress: false,
				allowedConns: map[*ipblock.IPBlock]*connection.Set{
					fromIPRangeStrWithoutValidation("10.250.10.0-10.250.10.3"):     connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        connection.None(),
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): connection.None(),
				},
				allowRules: map[*ipblock.IPBlock][]int{
					fromIPRangeStrWithoutValidation("10.250.10.0-10.250.10.3"):     {2},
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        {},
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): {},
				},
				deniedConns: map[*ipblock.IPBlock]*connection.Set{},
				denyRules:   map[*ipblock.IPBlock][]int{},
			},
			fromIPRangeStrWithoutValidation("10.240.10.2-10.240.10.3"): {
				isIngress: false,
				allowedConns: map[*ipblock.IPBlock]*connection.Set{
					fromIPRangeStrWithoutValidation("10.250.10.0-10.250.10.3"):     connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        connection.None(),
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): connection.None(),
				},
				allowRules: map[*ipblock.IPBlock][]int{
					fromIPRangeStrWithoutValidation("10.250.10.0-10.250.10.3"):     {2},
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        {},
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): {},
				},
				deniedConns: map[*ipblock.IPBlock]*connection.Set{},
				denyRules:   map[*ipblock.IPBlock][]int{},
			},
		},
	},
}

func (tt *sgTest) runTest(t *testing.T) {
	var endpoint1 = &NetworkInterface{InternalNode: vpcmodel.InternalNode{
		AddressStr: "10.240.10.1",
		IPBlockObj: fromIPAddressStrWithoutValidation("10.240.10.1"),
	}}
	var endpoint2 = &NetworkInterface{InternalNode: vpcmodel.InternalNode{
		AddressStr: "10.240.10.2",
		IPBlockObj: fromIPAddressStrWithoutValidation("10.240.10.2"),
	}}
	var endpoint3 = &NetworkInterface{InternalNode: vpcmodel.InternalNode{
		AddressStr: "10.240.10.0",
		IPBlockObj: fromIPAddressStrWithoutValidation("10.240.10.0"),
	}}

	sg := SecurityGroup{members: map[string]vpcmodel.Node{"10.240.10.1": endpoint1, "10.240.10.2": endpoint2, "10.240.10.0": endpoint3}}
	connectivityMap := mapAndAnalyzeSGRules(tt.rules, false, &sg)
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
	var endpoint1 = &NetworkInterface{InternalNode: vpcmodel.InternalNode{
		AddressStr: "10.240.10.1",
		IPBlockObj: fromIPAddressStrWithoutValidation("10.240.10.1"),
	}}

	sg := SecurityGroup{members: map[string]vpcmodel.Node{"10.240.10.1": endpoint1}}

	rulesTest1 := []*SGRule{
		{
			remote:      ruleTarget{sgName: "ola", cidr: newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.1")},
			connections: c1,
			index:       1,
			local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.1"),
		},
		{
			remote:      ruleTarget{sgName: "ola", cidr: newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.0/30")},
			connections: c2,
			index:       2,
			local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.0/30"),
		},
	}

	egressConnectivityMap := mapAndAnalyzeSGRules(rulesTest1, false, &sg)

	// in this example we should get the same ConnectivityResult for both IPBlock 10.240.10.0 and 10.240.10.2-10.240.10.3
	var connectivityResult1, connectivityResult2 *ConnectivityResult
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
