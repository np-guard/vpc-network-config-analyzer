package ibmvpc

import (
	"fmt"
	"testing"

	tgw "github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
	"github.com/stretchr/testify/require"
)

func TestGetTransitConnectionFiltersForVPC(t *testing.T) {

	permit := "permit"
	deny := "deny"
	subnetA := "192.168.100.0/24"
	subnetB := "192.168.101.0/24"
	subnetC := "192.168.102.0/24"
	tc := &datamodel.TransitConnection{
		TransitConnection: tgw.TransitConnection{
			PrefixFiltersDefault: &permit,
			PrefixFilters: []tgw.TransitGatewayConnectionPrefixFilterReference{
				{
					Action: &deny,
					Prefix: &subnetA,
				},
			},
		},
	}
	vpc := &VPC{}
	vpc.subnetsList = []*Subnet{
		{cidr: subnetA, VPCResource: vpcmodel.VPCResource{ResourceUID: "A"}},
		{cidr: subnetB, VPCResource: vpcmodel.VPCResource{ResourceUID: "B"}},
		{cidr: subnetC, VPCResource: vpcmodel.VPCResource{ResourceUID: "C"}},
	}

	permittedSubnets, err := getTransitConnectionFiltersForVPC(tc, vpc)
	fmt.Printf("%v", permittedSubnets)
	require.Nil(t, err)
	require.True(t, permittedSubnets["B"])
	require.True(t, permittedSubnets["C"])
	require.False(t, permittedSubnets["A"])

}
