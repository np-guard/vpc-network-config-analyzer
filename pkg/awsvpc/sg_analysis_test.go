/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/models/pkg/netp"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func TestSGRule(t *testing.T) {
	sgJSON := `{
		"Description": "Allow all inbound traffic",
		"GroupId": "GroupId:10",
		"GroupName": "GroupName:11",
		"IpPermissions": [
			{
				"FromPort": null,
				"IpProtocol": "-1",
				"IpRanges": [
					{
						"CidrIp": "0.0.0.0/0",
						"Description": "allow all ingress"
					}
				],
				"Ipv6Ranges": [],
				"PrefixListIds": [],
				"ToPort": null,
				"UserIdGroupPairs": []
			}
		],
		"IpPermissionsEgress": [
			{
				"FromPort": null,
				"IpProtocol": "-1",
				"IpRanges": [
					{
						"CidrIp": "0.0.0.0/0",
						"Description": null
					}
				],
				"Ipv6Ranges": [
					{
						"CidrIpv6": "::/0",
						"Description": null
					}
				],
				"PrefixListIds": [],
				"ToPort": null,
				"UserIdGroupPairs": []
			}
		],
		"OwnerId": "OwnerId:8",
		"Tags": [],
		"VpcId": "VpcId:5"
	}`

	sg := types.SecurityGroup{}
	err := json.Unmarshal([]byte(sgJSON), &sg)
	require.Nil(t, err)
	sgResource := &commonvpc.SecurityGroup{
		VPCResource: vpcmodel.VPCResource{
			ResourceUID:  *sg.GroupId,
			ResourceType: ResourceTypeSG,
			VPCRef:       nil,
			Region:       "",
		},
		Analyzer: commonvpc.NewSGAnalyzer(NewSpecificAnalyzer(&sg)), Members: map[string]vpcmodel.Node{},
	}
	ruleStr, sgRule, _, err := sgResource.Analyzer.SgAnalyzer.GetSGRule(0)
	require.Nil(t, err)
	require.Equal(t, sgRule.Remote.Cidr.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.Index, 0)
	require.Equal(t, ruleStr, "index: 0, direction: inbound,  conns: protocol: all, ipRanges: 0.0.0.0/0\n")
	ruleStr, sgRule, _, err = sgResource.Analyzer.SgAnalyzer.GetSGRule(1)
	require.Nil(t, err)
	require.Equal(t, sgRule.Remote.Cidr.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.Index, 1)
	require.Equal(t, ruleStr, "index: 1, direction: outbound,  conns: protocol: all, ipRanges: 0.0.0.0/0\n")
}

func newSGobj(groupID, groupName, vpcID string, ipPermissions []types.IpPermission,
	ipPermissionsEgress []types.IpPermission) types.SecurityGroup {
	return types.SecurityGroup{GroupId: &groupID, GroupName: &groupName, IpPermissions: ipPermissions,
		IpPermissionsEgress: ipPermissionsEgress, VpcId: &vpcID}
}

func newIPPermission(fromPort, toPort int32, ipProtocol string, ipRanges []types.IpRange) types.IpPermission {
	return types.IpPermission{FromPort: &fromPort, ToPort: &toPort, IpProtocol: &ipProtocol, IpRanges: ipRanges}
}

func TestWithSgObj(t *testing.T) {
	// ingress params
	ingressRules := []types.IpPermission{}
	ipRanges := []types.IpRange{}
	cidr1 := "4.2.0.0/16"
	ipRanges = append(ipRanges, types.IpRange{CidrIp: &cidr1})
	ingressRules = append(ingressRules, newIPPermission(5, 1000, "tcp", ipRanges))

	// egressParams
	egressRules := []types.IpPermission{}
	egressIPRanges := []types.IpRange{}
	cidr2 := "0.0.0.0/0"
	egressIPRanges = append(egressIPRanges, types.IpRange{CidrIp: &cidr2})
	egressRules = append(egressRules, newIPPermission(23, 10030, "tcp", egressIPRanges))

	sg := newSGobj("22", "ola", "", ingressRules, egressRules)
	sgResource := &commonvpc.SecurityGroup{
		VPCResource: vpcmodel.VPCResource{
			ResourceUID:  *sg.GroupId,
			ResourceType: ResourceTypeSG,
			VPCRef:       nil,
			Region:       "",
		},
		Analyzer: commonvpc.NewSGAnalyzer(NewSpecificAnalyzer(&sg)), Members: map[string]vpcmodel.Node{},
	}
	ruleStr, sgRule, _, err := sgResource.Analyzer.SgAnalyzer.GetSGRule(0)
	require.Nil(t, err)
	require.Equal(t, sgRule.Remote.Cidr.String(), "4.2.0.0/16")
	require.Equal(t, sgRule.Index, 0)
	require.Equal(t, ruleStr, "index: 0, direction: inbound,  conns: protocol: tcp,  dstPorts: 5-1000, ipRanges: 4.2.0.0/16\n")
	ruleStr, sgRule, _, err = sgResource.Analyzer.SgAnalyzer.GetSGRule(1)
	require.Nil(t, err)
	require.Equal(t, sgRule.Remote.Cidr.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.Index, 1)
	require.Equal(t, ruleStr, "index: 1, direction: outbound,  conns: protocol: tcp,  dstPorts: 23-10030, ipRanges: 0.0.0.0/0\n")
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

func newIPBlockFromCIDROrAddressWithoutValidation(cidr string) *ipblock.IPBlock {
	res, _ := ipblock.FromCidrOrAddress(cidr)
	return res
}

var sgTests = []sgTest{
	{
		name: "test1",
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
					fromIPAddressStrWithoutValidation("10.250.10.0"): connection.TCPorUDPConnection(
						netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("10.250.10.2-10.250.10.3"): connection.TCPorUDPConnection(
						netp.ProtocolString("TCP"), 1, 100, 5, 1000),
					fromIPRangeStrWithoutValidation("0.0.0.0-10.250.9.255"):        connection.None(),
					fromIPRangeStrWithoutValidation("10.250.10.4-255.255.255.255"): connection.None(),
					fromIPAddressStrWithoutValidation("10.250.10.1"): connection.TCPorUDPConnection(netp.ProtocolString("TCP"), 1, 100, 5, 1000).
						Union(connection.TCPorUDPConnection(netp.ProtocolString("UDP"), 5, 87, 10, 3245)),
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

	sg := commonvpc.SecurityGroup{Members: map[string]vpcmodel.Node{
		"10.240.10.1": endpoint1, "10.240.10.2": endpoint2, "10.240.10.0": endpoint3}}
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
