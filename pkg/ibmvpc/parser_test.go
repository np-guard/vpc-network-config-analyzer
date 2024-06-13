/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/ipblock"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func TestVPCResourceModelRegion(t *testing.T) {
	rc, err := ParseResourcesFromFile(filepath.Join(getTestsDirInput(), "input_multi_regions.json"))
	require.Nilf(t, err, "err: %s", err)

	vpcConfigs := vpcmodel.NewMultipleVPCConfigs("cloud name")
	regionToStructMap := make(map[string]*Region)
	err = getVPCconfig(rc, vpcConfigs, nil, regionToStructMap)
	require.Nilf(t, err, "err: %s", err)

	vpcConfig := vpcConfigs.Config("crn:41")
	require.Equal(t, vpcConfig.VPC.(*VPC).Region().name, "us-east")

	tgws := getTgwObjects(rc, vpcConfigs, "", nil, regionToStructMap)
	tgw := tgws["crn:595"]
	require.Equal(t, tgw.Region().name, "us-south")
}

func TestRegionMethodVPC(t *testing.T) {
	regionToStructMap := make(map[string]*Region) // map for caching Region objects
	vpcNodeSet := &VPC{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: "ola",
			ResourceUID:  "ola123",
			ResourceType: ResourceTypeVPC,
			Region:       "us-east",
		},
		nodes:           []vpcmodel.Node{},
		zones:           map[string]*Zone{},
		addressPrefixes: nil,
		region:          getRegionByName("us-east", regionToStructMap),
	}
	region := vpcNodeSet.Region()
	require.Equal(t, region.name, "us-east")
}

func TestRegionMethodTGW(t *testing.T) {
	regionToStructMap := make(map[string]*Region) // map for caching Region objects
	tgw := &TransitGateway{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: "tgwName",
			ResourceUID:  "tgwUID",
			ResourceType: ResourceTypeTGW,
			Region:       "us-east",
		},
		vpcs:            nil,
		availableRoutes: map[string][]*ipblock.IPBlock{},
		region:          getRegionByName("us-east", regionToStructMap),
	}
	region := tgw.Region()
	require.Equal(t, region.name, "us-east")
}

func TestGetRegionByName(t *testing.T) {
	regionToStructMap := make(map[string]*Region) // map for caching Region objects
	getRegionByName("us-south", regionToStructMap)
	getRegionByName("us-south", regionToStructMap)
	getRegionByName("us-east", regionToStructMap)
	getRegionByName("us-east", regionToStructMap)
	getRegionByName("us-east", regionToStructMap)
	getRegionByName("us-east", regionToStructMap)
	getRegionByName("", regionToStructMap)
	require.Equal(t, len(regionToStructMap), 3)

	region1 := getRegionByName("us-south", regionToStructMap)
	region2 := getRegionByName("us-south", regionToStructMap)
	require.Equal(t, region1, region2)
	require.True(t, region1 == region2)
}

func TestSubnetsBlocks(t *testing.T) {
	subnetsBlocks := subnetsIPBlocks{}
	subnetID, vpcID := "subId1", "vpcId"
	subnetOrigBlock, _ := ipblock.FromCidr("10.240.0.0/23")
	subnetsBlocks[subnetID] = &oneSubnetBlocks{subnetOriginalBlock: subnetOrigBlock}
	filtersBlocks := filtersBlocks{}
	filterBlock1, _ := ipblock.FromCidr("10.230.0.0/23")
	filterBlock2, _ := ipblock.FromCidr("10.240.0.0/24")
	filterBlock3, _ := ipblock.FromCidr("10.240.1.0/25")
	filterBlock4, _ := ipblock.FromCidr("10.240.1.128/25")

	filtersBlocks[vpcID] = []*ipblock.IPBlock{filterBlock1, filterBlock2, filterBlock3, filterBlock4}
	filtersBlocks.disjointBlocks()
	subnetsBlocks[subnetID].splitByFiltersBlocks = splitSubnetOriginalBlock(subnetsBlocks[subnetID].subnetOriginalBlock, filtersBlocks[vpcID])
	subnetsBlocks[subnetID].freeAddressesBlocks = subnetsBlocks[subnetID].splitByFiltersBlocks
	require.True(t, len(subnetsBlocks.subnetBlocks(subnetID)) == 3)
	blockIndexes := []int{0, 0, 1, 2, 1, 2, 1}
	allocatedAddresses := make([]string, len(blockIndexes))
	for i, blockIndex := range blockIndexes {
		address, _ := subnetsBlocks.allocSubnetFreeAddress(subnetID, blockIndex)
		allocatedAddresses[i] = address
	}
	slices.Sort(allocatedAddresses)
	expectedResult := []string{
		"10.240.0.0",
		"10.240.0.1",
		"10.240.1.0",
		"10.240.1.1",
		"10.240.1.128",
		"10.240.1.129",
		"10.240.1.130",
	}
	require.Equal(t, expectedResult, allocatedAddresses)
}
