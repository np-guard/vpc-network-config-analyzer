/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package awsvpc

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"

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
