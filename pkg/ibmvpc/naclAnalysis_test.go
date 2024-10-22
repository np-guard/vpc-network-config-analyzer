/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc/testfunc"
)

func TestGetRules(t *testing.T) {
	rc := NewIBMresourcesContainer()
	err := rc.ParseResourcesFromFile(filepath.Join(testfunc.GetTestsDirInput(), "input_acl_testing3.json"))
	require.Nilf(t, err, "err: %s", err)
	vpcConfigs, err := rc.VPCConfigsFromResources("", nil, nil)
	require.Nilf(t, err, "err: %s", err)
	for _, config := range vpcConfigs.Configs() {
		for _, f := range config.FilterResources {
			if naclLayer, ok := f.(*commonvpc.NaclLayer); ok {
				for _, nacl := range naclLayer.NaclList {
					testSingleNACL(nacl)
				}
			}
		}
	}
}

func testSingleNACL(nacl *commonvpc.NACL) {
	// test addAnalysisPerSubnet
	for _, subnet := range nacl.Subnets {
		nacl.Analyzer.AddAnalysisPerSubnet(subnet)
		// functions to test
		// AnalyzeNACLRulesPerDisjointTargets
		// getAllowedXgressConnections
	}
}

func TestGetAllowedXgressConnections(t *testing.T) {
	rulesTest1 := []*commonvpc.NACLRule{
		{
			Src:         newIPBlockFromCIDROrAddressWithoutValidation("1.2.3.4/32"),
			Dst:         newIPBlockFromCIDROrAddressWithoutValidation("10.0.0.1/32"),
			Connections: connection.All(),
			Action:      "deny",
		},
		{
			Src:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Dst:         newIPBlockFromCIDROrAddressWithoutValidation("0.0.0.0/0"),
			Connections: connection.All(),
			Action:      "allow",
		},
	}
	//nolint:all
	/*nolint
	rulesTest2 := []*NACLRule{
		{
			src:         common.FromCidr("1.2.3.4/32"),
			dst:         common.FromCidr("10.0.0.1/32"),
			connections: getTCPconn(80, 80),
			action:      "allow",
		},
		{
			src:         common.FromCidr("1.2.3.4/32"),
			dst:         common.FromCidr("10.0.0.1/32"),
			connections: getTCPconn(1, 100),
			action:      "deny",
		},
		{
			src:         common.FromCidr("0.0.0.0/0"),
			dst:         common.FromCidr("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	rulesTest3 := []*NACLRule{
		{
			dst:         common.FromCidr("1.2.3.4/32"),
			src:         common.FromCidr("10.0.0.1/32"),
			connections: getAllConnSet(),
			action:      "deny",
		},
		{
			dst:         common.FromCidr("0.0.0.0/0"),
			src:         common.FromCidr("0.0.0.0/0"),
			connections: getAllConnSet(),
			action:      "allow",
		},
	}

	subnet := common.FromCidr("10.0.0.0/24")

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
		naclRules     []*commonvpc.NACLRule
		src           []string
		dst           []string
		expectedConns []*connection.Set
	}{
		{
			testName:      "a",
			naclRules:     rulesTest1,
			src:           []string{"1.1.1.1/32", "1.2.3.4/32", "1.2.3.4/32"},
			dst:           []string{"10.0.0.0/24", "10.0.0.1/32", "10.0.0.0/32"},
			expectedConns: []*connection.Set{connection.All(), connection.None(), connection.All()},
		},
	}

	for _, tt := range tests {
		require.Equal(t, len(tt.src), len(tt.dst))
		require.Equal(t, len(tt.src), len(tt.expectedConns))
		for i := range tt.src {
			src := newIPBlockFromCIDROrAddressWithoutValidation(tt.src[i])
			dst := newIPBlockFromCIDROrAddressWithoutValidation(tt.dst[i])
			disjointPeers := []*ipblock.IPBlock{dst}
			expectedConn := tt.expectedConns[i]
			res, _, _, _ := commonvpc.GetAllowedXgressConnections(tt.naclRules, src, dst, disjointPeers, true)
			dstStr := dst.ToIPRanges()
			actualConn := res[dstStr]
			require.True(t, expectedConn.Equal(actualConn))
		}
	}

	//nolint:all
	/*src := common.FromCidr("1.1.1.1/32")
	dst := common.FromCidr("10.0.0.0/24")
	disjointPeers := []*ipblock.IPBlock{dst}
	res := commonvpc.GetAllowedXgressConnections(rulesTest1, src, dst, disjointPeers, true)
	for d, c := range res {
		fmt.Printf("%s => %s : %s\n", src.ToIPAdress(), d, c.String())
		require.True(t, c.Equal(getAllConnSet()))
	}*/

	fmt.Printf("done\n")
}
