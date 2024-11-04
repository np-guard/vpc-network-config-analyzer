/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/netset"
)

func TestSubnetsBlocks(t *testing.T) {
	subnetsBlocks := subnetsIPBlocks{}
	subnetID, vpcID := "subId1", "vpcId"
	subnetOrigBlock, _ := netset.IPBlockFromCidr("10.240.0.0/23")
	subnetsBlocks[subnetID] = &oneSubnetBlocks{subnetOriginalBlock: subnetOrigBlock}
	filtersCidrs := map[string][]string{}

	filtersCidrs[vpcID] = []string{"10.230.0.0/23", "10.240.0.1", "10.240.0.0/24", "10.240.1.0/25", "10.240.1.128/25"}
	filtersBlocks, _ := disjointVpcCidrs(filtersCidrs)
	subnetsBlocks[subnetID].splitByFiltersBlocks = splitSubnetOriginalBlock(subnetsBlocks[subnetID].subnetOriginalBlock, filtersBlocks[vpcID])
	subnetsBlocks[subnetID].freeAddressesBlocks = subnetsBlocks[subnetID].splitByFiltersBlocks
	require.True(t, len(subnetsBlocks.subnetBlocks(subnetID)) == 4)
	blockIndexes := []int{0, 1, 0, 1, 2, 3, 2, 3, 2}
	allocatedAddresses := make([]string, len(blockIndexes))
	for i, blockIndex := range blockIndexes {
		address, _ := subnetsBlocks.allocSubnetFreeAddress(subnetID, blockIndex)
		allocatedAddresses[i] = address
	}
	slices.Sort(allocatedAddresses)
	expectedResult := []string{
		"",
		"10.240.0.0",
		"10.240.0.1",
		"10.240.0.2",
		"10.240.1.0",
		"10.240.1.1",
		"10.240.1.128",
		"10.240.1.129",
		"10.240.1.130",
	}
	require.Equal(t, expectedResult, allocatedAddresses)
}
