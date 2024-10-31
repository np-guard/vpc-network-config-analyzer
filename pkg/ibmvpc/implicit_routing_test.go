/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type testImplicitRT struct {
	name         string
	dest         *netset.IPBlock
	expectedPath vpcmodel.Path
}

// the configuration

var vpc = &commonvpc.VPC{
	InternalAddressRange:   newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.0/24"),
	AddressPrefixesIPBlock: newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.0/24"),
}
var n1, _ = commonvpc.NewNetworkInterface("n1", "n1", "zone1", "10.10.2.6", "n1VSI", 1, false, vpc)
var n2, _ = commonvpc.NewNetworkInterface("n2", "n2", "zone1", "10.10.2.5", "n2VSI", 1, false, vpc)
var vpcConfig = &vpcmodel.VPCConfig{
	VPC:   vpc,
	Nodes: nodesFromNetIntfs([]*commonvpc.NetworkInterface{n1, n2}),
}

func nodesFromNetIntfs(nodes []*commonvpc.NetworkInterface) (res []vpcmodel.Node) {
	for _, n := range nodes {
		res = append(res, n)
	}
	return res
}

var implicitRTTets = []*testImplicitRT{
	{
		// basic test1: path exists to internal node in vpc (checking it has a subnet)
		name:         "path_exists_two_internal_nodes",
		dest:         newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.5/32"),
		expectedPath: vpcmodel.Path([]*vpcmodel.Endpoint{{VpcResource: n1}, {VpcResource: n2}}),
		// {IPBlock: newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.5/32")}}),
	},
	{
		// basic test2: path does not exist to destination outside the vpc
		name:         "path_does_not_exist_dest_outside_vpc",
		dest:         newIPBlockFromCIDROrAddressWithoutValidation("10.20.2.5/32"),
		expectedPath: nil,
	},
}

func TestImplicitRoutingTable(t *testing.T) {
	a := systemImplicitRT{vpc: vpc, config: &systemRTConfig{}, vpcConfig: vpcConfig}

	for _, tt := range implicitRTTets {
		actualPath := a.getEgressPath(n1, tt.dest)
		if tt.expectedPath == nil {
			require.Nil(t, actualPath)
		} else {
			require.True(t, tt.expectedPath.Equal(actualPath))
		}
	}
}
