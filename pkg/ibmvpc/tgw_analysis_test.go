package ibmvpc

import (
	"fmt"
	"testing"

	tgw "github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/stretchr/testify/require"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

var permit string = permitAction
var deny string = denyAction
var subnetA string = "192.168.100.0/24"
var subnetB string = "192.168.101.0/24"
var subnetC string = "192.168.102.0/24"
var subnetD string = "10.10.10.192/26"
var subnetE string = "10.10.10.0/24"
var subnetF string = "10.10.10.0/28"
var prefix string = "192.168.100.0/20"
var prefix2 string = "192.168.100.0/21"
var prefix3 string = "192.168.100.0/22"

var le int64 = 32
var ge int64 = 21
var le1 int64 = 22

type tgwTest struct {
	name                     string
	vpc                      *VPC
	tc                       *datamodel.TransitConnection
	expectedPermittedSubnets []string
	expectedFilteredSubnets  []string
}

func newVPCWithSubnets(uidTocidrs map[string]string) *VPC {
	vpc := &VPC{}
	for uid, cidr := range uidTocidrs {
		vpc.subnetsList = append(vpc.subnetsList, &Subnet{cidr: cidr, VPCResource: vpcmodel.VPCResource{ResourceUID: uid}})
	}
	return vpc
}

var tgwTests = []tgwTest{
	{
		name: "block_specific_routes_allow_by_default",
		vpc: newVPCWithSubnets(map[string]string{
			"A": subnetA,
			"B": subnetB,
			"C": subnetC,
		}),
		tc: &datamodel.TransitConnection{
			TransitConnection: tgw.TransitConnection{
				PrefixFiltersDefault: &permit,
				PrefixFilters: []tgw.TransitGatewayConnectionPrefixFilterReference{
					{
						Action: &deny,
						Prefix: &subnetA,
					},
				},
			},
		},
		expectedPermittedSubnets: []string{"B", "C"},
		expectedFilteredSubnets:  []string{"A"},
	},
	{
		name: "allow_specific_routes_block_by_default",
		vpc: newVPCWithSubnets(map[string]string{
			"A": subnetA,
			"B": subnetB,
			"C": subnetC,
		}),
		tc: &datamodel.TransitConnection{
			TransitConnection: tgw.TransitConnection{
				PrefixFiltersDefault: &deny,
				PrefixFilters: []tgw.TransitGatewayConnectionPrefixFilterReference{
					{
						Action: &permit,
						Prefix: &subnetA,
					},
				},
			},
		},
		expectedPermittedSubnets: []string{"A"},
		expectedFilteredSubnets:  []string{"B", "C"},
	},
	{
		name: "default_permit_empty_prefix_list",
		vpc: newVPCWithSubnets(map[string]string{
			"A": subnetA,
			"B": subnetB,
			"C": subnetC,
		}),
		tc: &datamodel.TransitConnection{
			TransitConnection: tgw.TransitConnection{
				PrefixFiltersDefault: &permit,
				PrefixFilters:        []tgw.TransitGatewayConnectionPrefixFilterReference{},
			},
		},
		expectedPermittedSubnets: []string{"A", "B", "C"},
		expectedFilteredSubnets:  []string{},
	},
	{
		name: "prefix_list_with_mixed_permit_deny_rules",
		vpc: newVPCWithSubnets(map[string]string{
			"A": subnetA,
			"B": subnetB,
			"C": subnetC,
			"D": subnetD,
			"E": subnetE,
			"F": subnetF,
		}),
		tc: &datamodel.TransitConnection{
			TransitConnection: tgw.TransitConnection{
				PrefixFiltersDefault: &deny,
				PrefixFilters: []tgw.TransitGatewayConnectionPrefixFilterReference{
					{
						Action: &deny,
						Prefix: &subnetD,
					},
					{
						Action: &permit,
						Prefix: &subnetE,
					},
					{
						Action: &permit,
						Prefix: &subnetE,
						Le:     &le,
					},
					{
						Action: &permit,
						Prefix: &subnetA,
					},
				},
			},
		},
		expectedPermittedSubnets: []string{"A", "E", "F"},
		expectedFilteredSubnets:  []string{"B", "C", "D"},
	},
	{
		name: "prefix_filter_with_ge",
		vpc: newVPCWithSubnets(map[string]string{
			"A": subnetA,
			"B": subnetB,
			"C": subnetC,
			"D": subnetD,
			"E": subnetE,
			"F": subnetF,
			"G": prefix,
			"H": prefix2,
			"I": prefix3,
		}),
		tc: &datamodel.TransitConnection{
			TransitConnection: tgw.TransitConnection{
				PrefixFiltersDefault: &deny,
				PrefixFilters: []tgw.TransitGatewayConnectionPrefixFilterReference{
					{
						Action: &permit,
						Prefix: &prefix,
						Ge:     &ge,
					},
				},
			},
		},
		expectedPermittedSubnets: []string{"A", "B", "C", "H", "I"},
		expectedFilteredSubnets:  []string{"D", "E", "F", "G"},
	},
	{
		name: "prefix_filter_with_le_and_ge",
		vpc: newVPCWithSubnets(map[string]string{
			"A": subnetA,
			"B": subnetB,
			"C": subnetC,
			"D": subnetD,
			"E": subnetE,
			"F": subnetF,
			"G": prefix,
			"H": prefix2,
			"I": prefix3,
		}),
		tc: &datamodel.TransitConnection{
			TransitConnection: tgw.TransitConnection{
				PrefixFiltersDefault: &deny,
				PrefixFilters: []tgw.TransitGatewayConnectionPrefixFilterReference{
					{
						Action: &permit,
						Prefix: &prefix,
						Ge:     &ge,
						Le:     &le1,
					},
				},
			},
		},
		expectedPermittedSubnets: []string{"H", "I"},
		expectedFilteredSubnets:  []string{"A", "B", "C", "D", "E", "F", "G"},
	},
}

func (tt *tgwTest) runTest(t *testing.T) {
	permittedSubnets, err := getTransitConnectionFiltersForVPC(tt.tc, tt.vpc)
	require.Nil(t, err)
	for _, s := range tt.expectedPermittedSubnets {
		require.True(t, permittedSubnets[s])
	}
	for _, s := range tt.expectedFilteredSubnets {
		require.False(t, permittedSubnets[s])
	}
}

func TestGetTransitConnectionFiltersForVPC(t *testing.T) {
	for testIdx := range tgwTests {
		tt := tgwTests[testIdx]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.runTest(t)
		})
	}
	fmt.Println("done")
}
