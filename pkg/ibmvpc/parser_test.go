/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"path/filepath"
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

	vpcConfig := vpcConfigs.Vpc("crn:41")
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
