package ibmvpc

import (
	"path/filepath"
	"testing"

	"github.com/np-guard/models/pkg/ipblocks"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
	"github.com/stretchr/testify/require"
)

func TestVPCResourceModelRegion(t *testing.T) {
	rc, err := ParseResourcesFromFile(filepath.Join(getTestsDirInput(), "input_experiments_env.json"))
	require.Nilf(t, err, "err: %s", err)
	vpcConfigs, err := VPCConfigsFromResources(rc, "", "", nil, false)
	require.Nilf(t, err, "err: %s", err)
	vpcConfig := vpcConfigs["crn:17"]
	require.Equal(t, vpcConfig.VPC.RegionName(), "us-south")
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

	require.Equal(t, len(regionToStructMap), 2)
	require.Equal(t, getRegionByName("us-south", regionToStructMap), getRegionByName("us-south", regionToStructMap))
}
