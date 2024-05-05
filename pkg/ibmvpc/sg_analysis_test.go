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
	c1 := connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245)
	c2 := connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000)

	rulesTest1 := []*SGRule{
		{
			target:      newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.1"),
			connections: c1,
			index:       1,
			local:       ipblock.GetCidrAll(),
		},
		{
			target:      newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.0/30"),
			connections: c2,
			index:       2,
			local:       ipblock.GetCidrAll(),
		},
	}

	target1, _ := ipblock.FromCidrOrAddress("10.250.10.0")
	target2, _ := ipblock.FromCidrOrAddress("10.250.10.2")
	target3, _ := ipblock.FromCidrOrAddress("10.250.10.1")

	egressConnectivityMap := make(map[*ipblock.IPBlock]*ConnectivityResult)
	mapAndAnalyzeSGRules(rulesTest1, false, egressConnectivityMap)
	require.Equal(t, len(egressConnectivityMap), 1) // expecting size 1 because locals are only "0.0.0.0/0" in this example
	for _, connectivityResult := range egressConnectivityMap {
		for remote, conn := range connectivityResult.allowedConns {
			if target1.ContainedIn(remote) || target2.ContainedIn(remote) {
				require.True(t, conn.Equal(c2))
			}
			if target3.ContainedIn(remote) {
				require.True(t, c1.ContainedIn(conn) && c2.ContainedIn(conn))
			}
		}
	}
}

func TestLocalField(t *testing.T) {
	c1 := connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245)
	c2 := connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000)

	rulesTest1 := []*SGRule{
		{
			target:      newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.1"),
			connections: c1,
			index:       1,
			local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.1"),
		},
		{
			target:      newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.0/30"),
			connections: c2,
			index:       2,
			local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.0/30"),
		},
	}

	cidr2 := newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.0/30")
	cidr2t := newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.0/30")

	member1 := newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.0")
	member2 := newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.2")
	member3 := newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.1")

	target1 := newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.0")
	target2 := newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.2")
	target3 := newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.1")

	egressConnectivityMap := make(map[*ipblock.IPBlock]*ConnectivityResult)
	mapAndAnalyzeSGRules(rulesTest1, false, egressConnectivityMap)
	for local, connectivityResult := range egressConnectivityMap {
		for remote, conn := range connectivityResult.allowedConns {
			if !local.ContainedIn(cidr2) || !remote.ContainedIn(cidr2t) {
				// no connection
				continue
			}
			switch {
			case member1.ContainedIn(local):
				require.True(t, conn.Equal(c2))
			case member2.ContainedIn(local):
				require.True(t, conn.Equal(c2))
			case member3.ContainedIn(local):
				if target1.ContainedIn(remote) || target2.ContainedIn(remote) {
					require.True(t, conn.Equal(c2))
				}
				if target3.ContainedIn(remote) {
					require.True(t, c1.ContainedIn(conn) && c2.ContainedIn(conn))
				}
			}
		}
	}
}

func TestCaching(t *testing.T) {
	c1 := connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245)
	c2 := connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000)

	rulesTest1 := []*SGRule{
		{
			target:      newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.1"),
			connections: c1,
			index:       1,
			local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.1"),
		},
		{
			target:      newIPBlockFromCIDROrAddressWithoutValidation("10.250.10.0/30"),
			connections: c2,
			index:       2,
			local:       newIPBlockFromCIDROrAddressWithoutValidation("10.240.10.0/30"),
		},
	}

	egressConnectivityMap := make(map[*ipblock.IPBlock]*ConnectivityResult)
	mapAndAnalyzeSGRules(rulesTest1, false, egressConnectivityMap)

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
	require.True(t, connectivityResult1 == connectivityResult2)
}
