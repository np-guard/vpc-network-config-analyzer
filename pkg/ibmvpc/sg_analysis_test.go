/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"encoding/json"
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
		analyzer: NewSGAnalyzer(&sg.SecurityGroup), members: map[string]vpcmodel.Node{},
	}
	ruleStr, sgRule, _, err := sgResource.analyzer.getSGRule(0)
	require.Nil(t, err)
	require.Equal(t, sgRule.target.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.local.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.index, 0)
	require.Equal(t, ruleStr, "index: 0, direction: outbound,  conns: protocol: all, remote: 0.0.0.0/0, local: 0.0.0.0/0\n")
	ruleStr, sgRule, _, err = sgResource.analyzer.getSGRule(1)
	require.Nil(t, err)
	require.Equal(t, sgRule.target.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.local.String(), "10.240.10.0")
	require.Equal(t, sgRule.index, 1)
	require.Equal(t, ruleStr, "index: 1, direction: inbound,  conns: protocol: all, remote: 0.0.0.0/0, local: 10.240.10.0/32\n")
}

func TestNoLocalField(t *testing.T) {
	cidr1t, _ := ipblock.FromCidrOrAddress("10.250.10.1")
	cidr2t, _ := ipblock.FromCidrOrAddress("10.250.10.0/30")

	rulesTest1 := []*SGRule{
		{
			target:      cidr1t,
			connections: connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245),
			index:       1,
			local:       ipblock.GetCidrAll(),
		},
		{
			target:      cidr2t,
			connections: connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
			index:       2,
			local:       ipblock.GetCidrAll(),
		},
	}

	egressConnectivityMap := make(map[*ipblock.IPBlock]*ConnectivityResult)
	mapAndAnalyzeSGRules(rulesTest1, false, egressConnectivityMap)
	for _, CR := range egressConnectivityMap {
		stringCR := CR.string()
		require.Equal(t, stringCR, "remote: 0.0.0.0-10.250.9.255, conn: No Connections\n"+
			"remote: 10.250.10.0-10.250.10.0, conn: protocol: TCP src-ports: 1-100 dst-ports: 5-1000\n"+
			"remote: 10.250.10.1-10.250.10.1, conn: protocol: TCP src-ports: 1-100 dst-ports: 5-1000;"+
			" protocol: UDP src-ports: 5-87 dst-ports: 10-3245\n"+
			"remote: 10.250.10.2-10.250.10.3, conn: protocol: TCP src-ports: 1-100 dst-ports: 5-1000\n"+
			"remote: 10.250.10.4-255.255.255.255, conn: No Connections")
	}
}

func TestLocalField(t *testing.T) {
	cidr1, _ := ipblock.FromCidrOrAddress("10.240.10.1")
	cidr2, _ := ipblock.FromCidrOrAddress("10.240.10.0/30")
	cidr1t, _ := ipblock.FromCidrOrAddress("10.250.10.1")
	cidr2t, _ := ipblock.FromCidrOrAddress("10.250.10.0/30")

	rulesTest1 := []*SGRule{
		{
			target:      cidr1t,
			connections: connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245),
			index:       1,
			local:       cidr1,
		},
		{
			target:      cidr2t,
			connections: connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000),
			index:       2,
			local:       cidr2,
		},
	}

	egressConnectivityMap := make(map[*ipblock.IPBlock]*ConnectivityResult)
	mapAndAnalyzeSGRules(rulesTest1, false, egressConnectivityMap)
	fullString := ""
	for _, CR := range egressConnectivityMap {
		fullString += CR.string()
	}
	require.Equal(t, fullString, "remote: 0.0.0.0-10.250.9.255, conn: No Connections\n"+
		"remote: 10.250.10.0-10.250.10.0, conn: protocol: TCP src-ports: 1-100 dst-ports: 5-1000\n"+
		"remote: 10.250.10.1-10.250.10.1, conn: protocol: TCP src-ports: 1-100 dst-ports: 5-1000;"+
		" protocol: UDP src-ports: 5-87 dst-ports: 10-3245\n"+
		"remote: 10.250.10.2-10.250.10.3, conn: protocol: TCP src-ports: 1-100 dst-ports: 5-1000\n"+
		"remote: 10.250.10.4-255.255.255.255, conn: No Connectionsremote: 0.0.0.0-10.250.9.255, conn: No Connections\n"+
		"remote: 10.250.10.0-10.250.10.3, conn: protocol: TCP src-ports: 1-100 dst-ports: 5-1000\n"+
		"remote: 10.250.10.4-255.255.255.255, conn: No Connectionsremote: 0.0.0.0-10.250.9.255, conn: No Connections\n"+
		"remote: 10.250.10.0-10.250.10.3, conn: protocol: TCP src-ports: 1-100 dst-ports: 5-1000\n"+
		"remote: 10.250.10.4-255.255.255.255, conn: No Connectionsremote: 0.0.0.0-255.255.255.255,"+
		" conn: No Connectionsremote: 0.0.0.0-255.255.255.255, conn: No Connections")
}
