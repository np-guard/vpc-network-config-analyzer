package ibmvpc

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/ipblocks"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

func TestVPCResourceModelRegion(t *testing.T) {
	rc, err := ParseResourcesFromFile(filepath.Join(getTestsDirInput(), "input_multi_regions.json"))
	require.Nilf(t, err, "err: %s", err)

	vpcConfigs := make(map[string]*vpcmodel.VPCConfig)
	regionToStructMap := make(map[string]*Region)
	err = getVPCconfig(rc, vpcConfigs, nil, regionToStructMap)
	require.Nilf(t, err, "err: %s", err)

	vpcConfig := vpcConfigs["crn:41"]
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
		availableRoutes: map[string][]*ipblocks.IPBlock{},
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
	require.Equal(t, getRegionByName("us-south", regionToStructMap), getRegionByName("us-south", regionToStructMap))
	require.Equal(t, getRegionByName("us-east", regionToStructMap).name, getRegionByName("us-east", regionToStructMap).name)
}
