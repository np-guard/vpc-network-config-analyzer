/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// genConfig returns VPCConfig object (used for testing)
func genConfig(vpc *commonvpc.VPC, subnets []*commonvpc.Subnet,
	netInterfaces []*commonvpc.NetworkInterface,
	pgws []*PublicGateway,
	fips []*FloatingIP,
) *vpcmodel.VPCConfig {
	res := &vpcmodel.VPCConfig{}
	res.NodeSets = append(res.NodeSets, vpc)
	res.VPC = vpc
	for _, subnet := range subnets {
		res.NodeSets = append(res.NodeSets, subnet)
		// add references from subnet to nodes, and from node to subnet
		for _, node := range netInterfaces {
			if node.IPBlockObj.ContainedIn(subnet.AddressRange()) {
				subnet.VPCnodes = append(subnet.VPCnodes, node)
				node.SubnetResource = subnet
				// currently skipping nodes without subnets
				// currently not adding vsi objects
				res.Nodes = append(res.Nodes, node)
			}
		}
	}
	for _, pgw := range pgws {
		res.RoutingResources = append(res.RoutingResources, pgw)
	}
	for _, fip := range fips {
		res.RoutingResources = append(res.RoutingResources, fip)
	}
	return res
}

///////////////////////////////////////////////////////////////////////////////////////////////////

type routesPerSubnets struct {
	routesMap map[string][]*route // map from list of subnets to routes in their egress RT
}

const comma = ","

func subnetsKeyToSubnets(key string, config *vpcmodel.VPCConfig) []*commonvpc.Subnet {
	res := []*commonvpc.Subnet{}
	subnetNames := strings.Split(key, comma)
	for _, nodeset := range config.NodeSets {
		if subnet, ok := nodeset.(*commonvpc.Subnet); ok {
			if slices.Contains(subnetNames, subnet.ResourceName) {
				res = append(res, subnet)
			}
		}
	}
	return res
}

var emptyRoutes = []*route{} // default routing table is empty

var emptyRoutesAllSubnets = &routesPerSubnets{
	routesMap: map[string][]*route{
		strings.Join([]string{"subnet1", "subnet2", "subnet3"}, comma): emptyRoutes,
	},
}

var routes1 = []*route{
	newRouteNoErr("r1", "0.0.0.0/0", "10.10.1.5", deliver, 2, "zoneA"),
	newRouteNoErr("r2", "10.10.0.0/16", "", delegate, 2, "zoneA"),
	newRouteNoErr("r3", "10.11.0.0/16", "", delegate, 2, "zoneB"),
	newRouteNoErr("r4", "0.0.0.0/0", "10.10.1.5", deliver, 2, "zoneB"),
}

var routes1PartialSubnets = &routesPerSubnets{
	routesMap: map[string][]*route{
		"subnet2" + "," + "subnet3": emptyRoutes,
		"subnet1":                   routes1, // changes routing for this subnet
	},
}

func newEgressRTFromRoutes(rps *routesPerSubnets, config *vpcmodel.VPCConfig, vpc *commonvpc.VPC) []*egressRoutingTable {
	res := []*egressRoutingTable{}
	for subnetsKey, routes := range rps.routesMap {
		egressRT := &egressRoutingTable{}
		implicitRT := &systemImplicitRT{vpc: vpc, config: systemRTConfigFromVPCConfig(config), vpcConfig: config}
		if rt, err := newRoutingTable(routes, implicitRT, &vpcmodel.VPCResource{}); err == nil {
			egressRT.routingTable = *rt
		}
		egressRT.vpc = vpc
		egressRT.subnets = subnetsKeyToSubnets(subnetsKey, config)
		res = append(res, egressRT)
	}
	return res
}

func newBasicConfig(rps *routesPerSubnets) (*vpcmodel.VPCConfig, []*egressRoutingTable) {
	vpc1, _ := commonvpc.NewVPC("vpc1", "vpc1", "", map[string][]string{"zoneA": {"10.10.0.0/16"},
		"zoneB": {"10.11.0.0/16"}}, map[string]*commonvpc.Region{})
	subnet1, _ := commonvpc.NewSubnet("subnet1", "subnet1", "zoneA", "10.10.1.0/24", vpc1)
	subnet2, _ := commonvpc.NewSubnet("subnet2", "subnet2", "zoneA", "10.10.3.0/24", vpc1)
	subnet3, _ := commonvpc.NewSubnet("subnet3", "subnet3", "zoneA", "10.10.0.0/24", vpc1)
	node1, _ := commonvpc.NewNetworkInterface("node1", "node1", "zoneA", "10.10.1.8", "vsi1", 1, false, vpc1)
	node2, _ := commonvpc.NewNetworkInterface("node2", "node2", "zoneA", "10.10.3.8", "vsi2", 1, false, vpc1)
	// 2 nodes below - same vsi, different network interfaces
	node3, _ := commonvpc.NewNetworkInterface("node3", "node3", "zoneA", "10.10.1.5", "vsi3", 2, false, vpc1)
	node4, _ := commonvpc.NewNetworkInterface("node4", "node4", "zoneA", "10.10.0.5", "vsi3", 2, false, vpc1)

	allSubnets := []*commonvpc.Subnet{subnet1, subnet2, subnet3}
	allNodes := []*commonvpc.NetworkInterface{node1, node2, node3, node4}

	pgwToSubnet := map[string][]*commonvpc.Subnet{"pgw1": {subnet1, subnet2}}
	pgw := newPGW("pgw1", "pgw1", "zoneA", pgwToSubnet, vpc1)
	fip := newFIP("fip1", "fip1", "zoneA", "", vpc, []vpcmodel.Node{node4})

	config := genConfig(vpc1,
		allSubnets,
		allNodes,
		[]*PublicGateway{pgw},
		[]*FloatingIP{fip},
	)

	return config, newEgressRTFromRoutes(rps, config, vpc1)
}

type testRTAnalyzer struct {
	testName     string
	rps          *routesPerSubnets
	srcIP        string
	dstIP        string
	expectedErr  string
	expectedPath vpcmodel.Path
}

func (test *testRTAnalyzer) run(t *testing.T) {
	// build config and routing tables from test
	config1, egressRT1 := newBasicConfig(test.rps)
	for _, rt := range egressRT1 {
		vpcmodel.AddRoutingTable(config1, rt)
	}

	rtAnalyzer1 := newRTAnalyzer(config1)
	path1, err1 := rtAnalyzer1.getEgressPathFromAddressSrc(
		newIPBlockFromCIDROrAddressWithoutValidation(test.srcIP),
		newIPBlockFromCIDROrAddressWithoutValidation(test.dstIP))

	// check err
	if test.expectedErr == "" {
		require.Nil(t, err1)
	} else {
		require.NotNil(t, err1)
		require.Contains(t, err1.Error(), test.expectedErr)
	}

	// check path
	if test.expectedPath.Empty() {
		require.Nil(t, path1)
	} else {
		require.NotNil(t, path1)
		fmt.Printf("expected path: %s\n actual path: %s\n", test.expectedPath.String(), path1.String())
		require.True(t, path1.Equal(test.expectedPath))
	}
}

func newNetIntForTest(vsi, address, nodeName string,
	numberOfNifs int) *commonvpc.NetworkInterface { //nolint:unparam // numberOfNifs is param
	res, _ := commonvpc.NewNetworkInterface(nodeName, nodeName, "zoneA", address, vsi, numberOfNifs, false, &commonvpc.VPC{})
	return res
}

var testRTAnalyzerTests = []*testRTAnalyzer{
	// good path tests - with emptyRoutesAllSubnets (default routing table to all subnets )
	// TODO: identify dest as node (internal/external), and improve address/name str
	{
		testName:    "path from internal src to internal dst in the same vpc, different subnet",
		rps:         emptyRoutesAllSubnets,
		srcIP:       "10.10.1.8",
		dstIP:       "10.10.3.8",
		expectedErr: "",
		expectedPath: vpcmodel.Path([]*vpcmodel.Endpoint{{VpcResource: newNetIntForTest("vsi1", "10.10.1.8", "node1", 1)},
			{VpcResource: newNetIntForTest("vsi2", "10.10.3.8", "node2", 1)},
			/*{IPBlock: newIPBlockFromCIDROrAddressWithoutValidation("10.10.3.8")}*/}), // (derived from system implicit RT )
	},

	{
		testName:    "dest is public internet address, path is through pgw (implicit RT)",
		rps:         emptyRoutesAllSubnets,
		srcIP:       "10.10.1.8",
		dstIP:       "8.8.8.8",
		expectedErr: "",
		expectedPath: vpcmodel.Path([]*vpcmodel.Endpoint{{VpcResource: newNetIntForTest("vsi1", "10.10.1.8", "node1", 1)},
			{VpcResource: newPGW("pgw1", "pgw1", "zoneA", nil, &commonvpc.VPC{})},
			{IPBlock: newIPBlockFromCIDROrAddressWithoutValidation("8.8.8.8")}}), // (derived from system implicit RT )
	},

	{
		testName:    "dest is public internet address, path is through fip (implicit RT)",
		rps:         emptyRoutesAllSubnets,
		srcIP:       "10.10.0.5",
		dstIP:       "8.8.8.8",
		expectedErr: "",
		expectedPath: vpcmodel.Path([]*vpcmodel.Endpoint{{VpcResource: newNetIntForTest("vsi3", "10.10.0.5", "node4", 1)},
			{VpcResource: newFIP("fip1", "fip1", "zoneA", "", &commonvpc.VPC{}, nil)},
			{IPBlock: newIPBlockFromCIDROrAddressWithoutValidation("8.8.8.8")}}), // (derived from system implicit RT )
	},

	// good path tests - with routes1PartialSubnets (not only default routing table to all subnets )
	{
		testName:    "dest is public internet address, path is redirected through subnet's RT (subnet1)",
		rps:         routes1PartialSubnets,
		srcIP:       "10.10.1.8",
		dstIP:       "8.8.8.8",
		expectedErr: "",
		expectedPath: vpcmodel.Path([]*vpcmodel.Endpoint{{VpcResource: newNetIntForTest("vsi1", "10.10.1.8", "node1", 1)},
			{NextHop: &vpcmodel.NextHopEntry{NextHop: newIPBlockFromCIDROrAddressWithoutValidation("10.10.1.5"),
				OrigDest: newIPBlockFromCIDROrAddressWithoutValidation("8.8.8.8")}}}), // derived from RT built from routes1
		// TODO: path from 10.10.1.5 -> external address : should be available via another network interface of the VSI (10.10.0.5) and then FIP ?
	},
	{
		testName:    "dest is vpc internal address, path is delegated through subnet's RT (subnet1)",
		rps:         routes1PartialSubnets,
		srcIP:       "10.10.1.8",
		dstIP:       "10.10.3.8",
		expectedErr: "",
		expectedPath: vpcmodel.Path([]*vpcmodel.Endpoint{{VpcResource: newNetIntForTest("vsi1", "10.10.1.8", "node1", 1)},
			{VpcResource: newNetIntForTest("vsi2", "10.10.3.8", "node2", 1)},
			/*{IPBlock: newIPBlockFromCIDROrAddressWithoutValidation("10.10.3.8")}*/}), // (derived from system implicit RT )
	},
	{
		testName:    "dest is public internet address, path is through pgw (default RT) (subnet2)",
		rps:         routes1PartialSubnets,
		srcIP:       "10.10.3.8",
		dstIP:       "8.8.8.8",
		expectedErr: "",
		expectedPath: vpcmodel.Path([]*vpcmodel.Endpoint{{VpcResource: newNetIntForTest("vsi2", "10.10.3.8", "node2", 1)},
			{VpcResource: newPGW("pgw1", "pgw1", "zoneA", nil, &commonvpc.VPC{})},
			{IPBlock: newIPBlockFromCIDROrAddressWithoutValidation("8.8.8.8")}}), // (derived from system implicit RT )
		// TODO: what about SG? which one is enforced?
	},

	// bad path tests
	{
		testName:    "src is not a valid internal node by address",
		rps:         emptyRoutesAllSubnets,
		srcIP:       "10.10.2.8",
		dstIP:       "10.10.3.8",
		expectedErr: "could not find internal node with address",
	},
}

func TestRTAnalyzerBasicNew(t *testing.T) {
	t.Parallel()
	for idx := range testRTAnalyzerTests {
		test := testRTAnalyzerTests[idx]
		t.Run(test.testName, func(t *testing.T) {
			t.Parallel()
			test.run(t)
		})
	}
}
