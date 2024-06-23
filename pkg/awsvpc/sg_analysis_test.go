/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
//nolint:lll // styles are too long and can not be split
package awsvpc

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/require"

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
	sgResource := &SecurityGroup{
		VPCResource: vpcmodel.VPCResource{
			ResourceUID:  *sg.GroupId,
			ResourceType: ResourceTypeSG,
			VPCRef:       nil,
			Region:       "",
		},
		analyzer: NewSGAnalyzer(&sg), members: map[string]vpcmodel.Node{},
	}
	ruleStr, sgRule, _, err := sgResource.analyzer.getSGRule(0)
	require.Nil(t, err)
	require.Equal(t, sgRule.ipRanges.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.index, 0)
	require.Equal(t, ruleStr, "index: 0, direction: inbound,  conns: protocol: -1, ipRanges: 0.0.0.0/0\n")
	ruleStr, sgRule, _, err = sgResource.analyzer.getSGRule(1)
	require.Nil(t, err)
	require.Equal(t, sgRule.ipRanges.String(), "0.0.0.0/0")
	require.Equal(t, sgRule.index, 1)
	require.Equal(t, ruleStr, "index: 1, direction: outbound,  conns: protocol: -1, ipRanges: 0.0.0.0/0\n")
}
