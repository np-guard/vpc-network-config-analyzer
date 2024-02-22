package ibmvpc

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/ipblocks"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

func TestGetRules(t *testing.T) {
	rc, err := ParseResourcesFromFile(filepath.Join(getTestsDirInput(), "input_acl_testing3.json"), "")
	require.Nilf(t, err, "err: %s", err)
	vpcConfigs, err := VPCConfigsFromResources(rc, "", false)
	require.Nilf(t, err, "err: %s", err)
	for _, config := range vpcConfigs {
		for _, f := range config.FilterResources {
			if naclLayer, ok := f.(*NaclLayer); ok {
				for _, nacl := range naclLayer.naclList {
					testSingleNACL(nacl)
				}
			}
		}
	}
}

func testSingleNACL(nacl *NACL) {
	// test addAnalysisPerSubnet
	for _, subnet := range nacl.subnets {
		nacl.analyzer.addAnalysisPerSubnet(subnet)
		// functions to test
		// AnalyzeNACLRulesPerDisjointTargets
		// getAllowedXgressConnections
	}
}

func TestGetAllowedXgressConnections(t *testing.T) {
	rulesTest1 := []*NACLRule{
		{
			src:         newIPBlockFromCIDROrAddressWithoutValidation("1.2.3.4/32"),
			dst:         newIPBlockFromCIDROrAddressWithoutValidation("10.0.0.1/32"),
			connections: getAllConnSet(),
			action:      "deny",
		},
		{
			src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}
	//nolint:all
	/*nolint
	rulesTest2 := []*NACLRule{
		{
			src:         common.NewIPBlockFromCidr("1.2.3.4/32"),
			dst:         common.NewIPBlockFromCidr("10.0.0.1/32"),
			connections: getTCPconn(80, 80),
			action:      "allow",
		},
		{
			src:         common.NewIPBlockFromCidr("1.2.3.4/32"),
			dst:         common.NewIPBlockFromCidr("10.0.0.1/32"),
			connections: getTCPconn(1, 100),
			action:      "deny",
		},
		{
			src:         common.NewIPBlockFromCidr("0.0.0.0/0"),
			dst:         common.NewIPBlockFromCidr("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	rulesTest3 := []*NACLRule{
		{
			dst:         common.NewIPBlockFromCidr("1.2.3.4/32"),
			src:         common.NewIPBlockFromCidr("10.0.0.1/32"),
			connections: getAllConnSet(),
			action:      "deny",
		},
		{
			dst:         common.NewIPBlockFromCidr("0.0.0.0/0"),
			src:         common.NewIPBlockFromCidr("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	subnet := common.NewIPBlockFromCidr("10.0.0.0/24")

	//res1 := ingressConnResFromInput(rulesTest1, subnet)
	res1, _ := AnalyzeNACLRules(rulesTest1, subnet, true, nil)
	fmt.Printf("res for test %s:\n%s\n", "rulesTest1", res1)

	//res2 := ingressConnResFromInput(rulesTest2, subnet)
	res2, _ := AnalyzeNACLRules(rulesTest2, subnet, true, nil)
	fmt.Printf("res for test %s:\n%s\n", "rulesTest2", res2)

	res3, _ := AnalyzeNACLRules(rulesTest3, subnet, false, nil)
	fmt.Printf("res for test %s:\n%s\n", "rulesTest3", res3)
	*/

	tests := []struct {
		testName      string
		naclRules     []*NACLRule
		src           []string
		dst           []string
		expectedConns []*common.ConnectionSet
	}{
		{
			testName:      "a",
			naclRules:     rulesTest1,
			src:           []string{"1.1.1.1/32", "1.2.3.4/32", "1.2.3.4/32"},
			dst:           []string{"10.0.0.0/24", "10.0.0.1/32", "10.0.0.0/32"},
			expectedConns: []*common.ConnectionSet{getAllConnSet(), getEmptyConnSet(), getAllConnSet()},
		},
	}

	for _, tt := range tests {
		require.Equal(t, len(tt.src), len(tt.dst))
		require.Equal(t, len(tt.src), len(tt.expectedConns))
		for i := range tt.src {
			src := newIPBlockFromCIDROrAddressWithoutValidation(tt.src[i])
			dst := newIPBlockFromCIDROrAddressWithoutValidation(tt.dst[i])
			disjointPeers := []*ipblocks.IPBlock{dst}
			expectedConn := tt.expectedConns[i]
			res, _, _, _ := getAllowedXgressConnections(tt.naclRules, src, dst, disjointPeers, true)
			dstStr := dst.ToIPRanges()
			actualConn := res[dstStr]
			require.True(t, expectedConn.Equal(actualConn))
		}
	}

	//nolint:all
	/*src := common.NewIPBlockFromCidr("1.1.1.1/32")
	dst := common.NewIPBlockFromCidr("10.0.0.0/24")
	disjointPeers := []*ipblocks.IPBlock{dst}
	res := getAllowedXgressConnections(rulesTest1, src, dst, disjointPeers, true)
	for d, c := range res {
		fmt.Printf("%s => %s : %s\n", src.ToIPAdress(), d, c.String())
		require.True(t, c.Equal(getAllConnSet()))
	}*/

	fmt.Printf("done\n")
}
