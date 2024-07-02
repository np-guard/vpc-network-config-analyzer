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

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func TestVPCResourceModelRegion(t *testing.T) {
	rc, err := parseResourcesFromFile(filepath.Join(getTestsDirInput(), "input_multi_regions.json"))
	require.Nilf(t, err, "err: %s", err)

	vpcConfigs := vpcmodel.NewMultipleVPCConfigs("cloud name")
	regionToStructMap := make(map[string]*commonvpc.Region)
	err = getVPCconfig(rc, vpcConfigs, nil, regionToStructMap)
	require.Nilf(t, err, "err: %s", err)

	vpcConfig := vpcConfigs.Config("crn:41")
	require.Equal(t, vpcConfig.VPC.(*commonvpc.VPC).Region().Name, "us-east")

	tgws := getTgwObjects(rc, vpcConfigs, "", nil, regionToStructMap)
	tgw := tgws["crn:595"]
	require.Equal(t, tgw.Region().Name, "us-south")
}

func TestRegionMethodVPC(t *testing.T) {
	regionToStructMap := make(map[string]*commonvpc.Region) // map for caching Region objects
	vpcNodeSet := &commonvpc.VPC{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: "ola",
			ResourceUID:  "ola123",
			ResourceType: ResourceTypeVPC,
			Region:       "us-east",
		},
		VPCnodes:               []vpcmodel.Node{},
		Zones:                  map[string]*commonvpc.Zone{},
		AddressPrefixesIPBlock: nil,
		VPCregion:              getRegionByName("us-east", regionToStructMap),
	}
	region := vpcNodeSet.Region()
	require.Equal(t, region.Name, "us-east")
}

func TestRegionMethodTGW(t *testing.T) {
	regionToStructMap := make(map[string]*commonvpc.Region) // map for caching Region objects
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
	require.Equal(t, region.Name, "us-east")
}

func TestGetRegionByName(t *testing.T) {
	regionToStructMap := make(map[string]*commonvpc.Region) // map for caching Region objects
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
