package ibmvpc

import (
	_ "embed"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	connection "github.com/np-guard/connectionlib/pkg/connection"
	ipblock "github.com/np-guard/connectionlib/pkg/ipblock"
)

//go:embed examples/input_acl_testing3.json
var acl3Input []byte

func TestGetRules(t *testing.T) {
	inputResourcesJSON := acl3Input
	rc, err := ParseResources(inputResourcesJSON)
	require.Nilf(t, err, "err: %s", err)
	cloudConfig, err := NewCloudConfig(rc)
	require.Nilf(t, err, "err: %s", err)
	for _, f := range cloudConfig.FilterResources {
		if naclLayer, ok := f.(*NaclLayer); ok {
			for _, nacl := range naclLayer.naclList {
				testSingleNACL(nacl)
			}
		}
	}
}

func testSingleNACL(nacl *NACL) {
	// test addAnalysisPerSubnet
	for subnet := range nacl.subnets {
		nacl.analyzer.addAnalysisPerSubnet(subnet)
		// functions to test
		// AnalyzeNACLRulesPerDisjointTargets
		// getAllowedXgressConnections
	}
}

func TestGetAllowedXgressConnections(t *testing.T) {
	rulesTest1 := []*NACLRule{
		{
			src:         ipblock.FromCIDR("1.2.3.4/32"),
			dst:         ipblock.FromCIDR("10.0.0.1/32"),
			connections: getAllConnSet(),
			action:      "deny",
		},
		{
			src:         ipblock.FromCIDR("0.0.0.0/0"),
			dst:         ipblock.FromCIDR("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}
	//nolint:all
	/*nolint
	rulesTest2 := []*NACLRule{
		{
			src:         ipblock.FromCIDR("1.2.3.4/32"),
			dst:         ipblock.FromCIDR("10.0.0.1/32"),
			connections: getTCPconn(80, 80),
			action:      "allow",
		},
		{
			src:         ipblock.FromCIDR("1.2.3.4/32"),
			dst:         ipblock.FromCIDR("10.0.0.1/32"),
			connections: getTCPconn(1, 100),
			action:      "deny",
		},
		{
			src:         ipblock.FromCIDR("0.0.0.0/0"),
			dst:         ipblock.FromCIDR("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	rulesTest3 := []*NACLRule{
		{
			dst:         ipblock.FromCIDR("1.2.3.4/32"),
			src:         ipblock.FromCIDR("10.0.0.1/32"),
			connections: getAllConnSet(),
			action:      "deny",
		},
		{
			dst:         ipblock.FromCIDR("0.0.0.0/0"),
			src:         ipblock.FromCIDR("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	subnet := ipblock.FromCIDR("10.0.0.0/24")

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
		expectedConns []*connection.Set
	}{
		{
			testName:      "a",
			naclRules:     rulesTest1,
			src:           []string{"1.1.1.1/32", "1.2.3.4/32", "1.2.3.4/32"},
			dst:           []string{"10.0.0.0/24", "10.0.0.1/32", "10.0.0.0/32"},
			expectedConns: []*connection.Set{getAllConnSet(), getEmptyConnSet(), getAllConnSet()},
		},
	}

	for _, tt := range tests {
		require.Equal(t, len(tt.src), len(tt.dst))
		require.Equal(t, len(tt.src), len(tt.expectedConns))
		for i := range tt.src {
			src, err := ipblock.FromCIDR(tt.src[i])
			dst, err := ipblock.FromCIDR(tt.dst[i])
			disjointPeers := []*ipblock.IPBlock{dst}
			expectedConn := tt.expectedConns[i]
			res := getAllowedXgressConnections(tt.naclRules, src, dst, disjointPeers, true)
			dstStr := strings.Join(dst.ToIPRanges(), ",")
			actualConn := res[dstStr]
			require.True(t, expectedConn.Equal(actualConn))
		}
	}

	//nolint:all
	/*src := ipblock.FromCIDR("1.1.1.1/32")
	dst := ipblock.FromCIDR("10.0.0.0/24")
	disjointPeers := []*ipblock.IPBlock{dst}
	res := getAllowedXgressConnections(rulesTest1, src, dst, disjointPeers, true)
	for d, c := range res {
		fmt.Printf("%s => %s : %s\n", src.ToIPAdress(), d, c.String())
		require.True(t, c.Equal(getAllConnSet()))
	}*/

	fmt.Printf("done\n")
}
