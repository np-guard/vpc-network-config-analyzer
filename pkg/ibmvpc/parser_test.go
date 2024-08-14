/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/cloud-resource-collector/pkg/common"
	"github.com/np-guard/models/pkg/ipblock"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func TestVPCResourceModelRegion(t *testing.T) {
	rc := IBMresourcesContainer{}
	err := rc.ParseResourcesFromFile(filepath.Join(commonvpc.GetTestsDirInput(), "input_multi_regions.json"))
	require.Nilf(t, err, "err: %s", err)

	vpcConfigs := vpcmodel.NewMultipleVPCConfigs(common.IBM)
	regionToStructMap := make(map[string]*commonvpc.Region)
	err = rc.getVPCconfig(vpcConfigs, nil, regionToStructMap)
	require.Nilf(t, err, "err: %s", err)

	vpcConfig := vpcConfigs.Config("crn:41")
	require.Equal(t, vpcConfig.VPC.(*commonvpc.VPC).Region().Name, "us-east")

	tgws := rc.getTgwObjects(vpcConfigs, "", nil, regionToStructMap)
	tgw := tgws["crn:595"]
	require.Equal(t, tgw.Region().Name, "us-south")
}

func TestRegionMethodVPC(t *testing.T) {
	regionToStructMap := make(map[string]*commonvpc.Region) // map for caching Region objects
	vpcNodeSet := &commonvpc.VPC{
		VPCResource: vpcmodel.VPCResource{
			ResourceName: "ola",
			ResourceUID:  "ola123",
			ResourceType: vpcmodel.ResourceTypeVPC,
			Region:       "us-east",
		},
		VPCnodes:               []vpcmodel.Node{},
		Zones:                  map[string]*commonvpc.Zone{},
		AddressPrefixesIPBlock: nil,
		VPCregion:              commonvpc.GetRegionByName("us-east", regionToStructMap),
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
			ResourceType: vpcmodel.ResourceTypeTGW,
			Region:       "us-east",
		},
		vpcs:            nil,
		availableRoutes: map[string][]*ipblock.IPBlock{},
		region:          commonvpc.GetRegionByName("us-east", regionToStructMap),
	}
	region := tgw.Region()
	require.Equal(t, region.Name, "us-east")
}

func TestGetRegionByName(t *testing.T) {
	regionToStructMap := make(map[string]*commonvpc.Region) // map for caching Region objects
	commonvpc.GetRegionByName("us-south", regionToStructMap)
	commonvpc.GetRegionByName("us-south", regionToStructMap)
	commonvpc.GetRegionByName("us-east", regionToStructMap)
	commonvpc.GetRegionByName("us-east", regionToStructMap)
	commonvpc.GetRegionByName("us-east", regionToStructMap)
	commonvpc.GetRegionByName("us-east", regionToStructMap)
	commonvpc.GetRegionByName("", regionToStructMap)
	require.Equal(t, len(regionToStructMap), 3)

	region1 := commonvpc.GetRegionByName("us-south", regionToStructMap)
	region2 := commonvpc.GetRegionByName("us-south", regionToStructMap)
	require.Equal(t, region1, region2)
	require.True(t, region1 == region2)
}
