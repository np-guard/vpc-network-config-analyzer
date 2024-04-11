/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

type testImplicitRT struct {
	name         string
	dest         *ipblock.IPBlock
	expectedPath vpcmodel.Path
}

// the configuration
var vpc = &VPC{
	internalAddressRange:   newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.0/24"),
	addressPrefixes:        []string{"10.10.2.0/24"},
	addressPrefixesIPBlock: newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.0/24"),
}
var srcEndpoint = &NetworkInterface{InternalNode: vpcmodel.InternalNode{
	AddressStr: "10.10.2.6/32",
}}

var implicitRTTets = []*testImplicitRT{
	{
		// basic test1: path exists to internal node in vpc (checking it has a subnet)
		name: "path_exists_two_internal_nodes",
		dest: newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.5/32"),
		expectedPath: vpcmodel.Path([]*vpcmodel.Endpoint{{VpcResource: srcEndpoint},
			{IPBlock: newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.5/32")}}),
	},
	{
		// basic test2: path does not exist to destination outside the vpc
		name:         "path_does_not_exist_dest_outside_vpc",
		dest:         newIPBlockFromCIDROrAddressWithoutValidation("10.20.2.5/32"),
		expectedPath: nil,
	},
}

func TestImplicitRoutingTable(t *testing.T) {
	a := systemImplicitRT{vpc: vpc, config: &systemRTConfig{}}

	for _, tt := range implicitRTTets {
		actualPath := a.getPath(srcEndpoint, tt.dest)
		if tt.expectedPath == nil {
			require.Nil(t, actualPath)
		} else {
			require.True(t, tt.expectedPath.Equal(actualPath))
		}
	}
}
