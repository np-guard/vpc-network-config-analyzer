package ibmvpc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func newNetIntForPathTest() *NetworkInterface {
	res, _ := newNetworkInterface("node1", "node1", "zoneA", "10.10.2.6", "vsi1", &VPC{})
	return res
}

type testPath struct {
	name           string
	p              path
	pathString     string
	otherPath      path
	otherPathEqual bool
}

func (tt *testPath) run(t *testing.T) {
	if tt.pathString != "" {
		require.Equal(t, tt.pathString, tt.p.string())
	}
	if len(tt.otherPath) > 0 {
		require.Equal(t, tt.otherPathEqual, tt.p.equal(tt.otherPath))
		require.True(t, !tt.otherPath.empty())
	} else {
		require.True(t, tt.otherPath.empty())
	}
}

var testPathList = []*testPath{
	// tests for paths string
	{
		name: "check path string with src Netintf and dst IPBlock",
		p: path([]*endpoint{{vpcResource: newNetIntForPathTest()},
			{ipBlock: newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.5/32")}}),

		pathString: "NetworkInterface - vsi1[10.10.2.6] -> 10.10.2.5",
	},
	{
		name: "check path string with src Netintf and nextHop afterwards",
		p: path([]*endpoint{{vpcResource: newNetIntForPathTest()},
			{nextHop: &nextHopEntry{
				nextHop:  newIPBlockFromCIDROrAddressWithoutValidation("10.11.2.5"),
				origDest: newIPBlockFromCIDROrAddressWithoutValidation("10.12.2.5"),
			}}}),

		pathString: "NetworkInterface - vsi1[10.10.2.6] -> nextHop: 10.11.2.5 [origDest: 10.12.2.5]",
	},

	// tests for paths equal/not-equal
	{
		name: "check path equality should be true",
		p: path([]*endpoint{{vpcResource: newNetIntForPathTest()},
			{ipBlock: newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.5/32")}}),

		otherPath: path([]*endpoint{{vpcResource: newNetIntForPathTest()},
			{ipBlock: newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.5/32")}}),

		otherPathEqual: true,
	},
	{
		name: "check path equality should be false",
		p: path([]*endpoint{{vpcResource: newNetIntForPathTest()},
			{ipBlock: newIPBlockFromCIDROrAddressWithoutValidation("10.10.2.5/32")}}),

		otherPath: path([]*endpoint{{vpcResource: newNetIntForPathTest()},
			{ipBlock: newIPBlockFromCIDROrAddressWithoutValidation("10.11.2.5/32")}}),

		otherPathEqual: false,
	},
}

func TestPathMethods(t *testing.T) {
	t.Parallel()
	for idx := range testPathList {
		test := testPathList[idx]
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			test.run(t)
		})
	}
}
