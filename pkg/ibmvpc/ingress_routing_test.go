/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"slices"
	"testing"

	tgw "github.com/IBM/networking-go-sdk/transitgatewayapisv1"
	"github.com/stretchr/testify/require"

	"github.com/np-guard/cloud-resource-collector/pkg/common"
	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

/*
ingress routing table:
src - Transit gateway - Allows ingress traffic from an IBM Cloud Transit Gateway to another VPC or classic infrastructure.
Optionally, you can advertise routes to a transit gateway, which are not in the address prefix range of the VPC.
*/

// test based on hub & spoke example
// see https://cloud.ibm.com/docs/solution-tutorials?topic=solution-tutorials-vpc-transit1#vpc-transit-router

// tgw-link: connect enterprise (mocked by "DL" VPC) to transit VPC
// tgw-spoke: connect spoke VPC with transit VPC
/*
Ingress routing table:
Zone 		Destination 	Next hop 		Advertise
-----------------------------------------------------
Dallas 1 	10.1.0.0/16 	10.1.15.197 	On
Dallas 2 	10.2.0.0/16 	10.2.15.197 	On
Dallas 3 	10.3.0.0/16 	10.3.15.197 	On
Dallas 1 	192.168.0.0/16 	10.1.15.197 	On
Dallas 2 	192.168.0.0/16 	10.2.15.197 	On
Dallas 3 	192.168.0.0/16 	10.3.15.197 	On
*/

// the configured routing table has impact on the TGW available routes table (more advertised routes with advertise=On)

func newTGWConn() *datamodel.TransitConnection {
	permit := permitAction
	//PrefixFiltersDefault: &permit,
	return &datamodel.TransitConnection{
		TransitConnection: tgw.TransitConnection{
			PrefixFiltersDefault: &permit,
		},
	}
}

func newTGWForTest(name string) *TransitGateway {
	return newTGW(name, name, "", map[string]*commonvpc.Region{}, nil)
}

func addTGWConfig(tgwObj *TransitGateway, configs *vpcmodel.MultipleVPCConfigs) {
	tgwConfig, _ := tgwObj.newConfigFromTGW(configs)
	configs.AddConfig(tgwConfig)
}

//nolint:unparam // currently `nextHop` always receives `"10.1.15.197", due to current test
func pathFromNextHopValues(nextHop, origDest string) vpcmodel.Path {
	n, _ := ipblock.FromCidrOrAddress(nextHop)
	o, _ := ipblock.FromCidrOrAddress(origDest)
	return []*vpcmodel.Endpoint{{NextHop: &vpcmodel.NextHopEntry{NextHop: n, OrigDest: o}}}
}

func newHubSpokeBase1Config() (*vpcmodel.MultipleVPCConfigs, *GlobalRTAnalyzer) {
	vpcTransit, _ := commonvpc.NewVPC("transit", "transit", "", map[string][]string{"us-south-1": {"10.1.15.0/24"},
		"us-south-2": {"10.2.15.0/24"}}, map[string]*commonvpc.Region{})
	vpcSpoke, _ := commonvpc.NewVPC("spoke", "spoke", "", map[string][]string{"us-south-1": {"10.1.0.0/24"},
		"us-south-2": {"10.2.0.0/24"}}, map[string]*commonvpc.Region{})
	vpcEnterprise, _ := commonvpc.NewVPC("enterprise", "enterprise", "",
		map[string][]string{"z1": {"192.168.0.0/16"}}, map[string]*commonvpc.Region{})

	workerSubnetTransit, _ := commonvpc.NewSubnet("workerSubnetTransit", "workerSubnetTransit", "us-south-1", "10.1.15.0/26", vpcTransit)
	workerSubnetSpoke, _ := commonvpc.NewSubnet("workerSubnetSpoke", "workerSubnetSpoke", "us-south-1", "10.1.0.0/26", vpcSpoke)
	workerSubnetEnterprise, _ := commonvpc.NewSubnet("workerSubnetEnterprise",
		"workerSubnetEnterprise", "z1", "192.168.0.0/16", vpcEnterprise)
	firewallSubnetTransit, _ := commonvpc.NewSubnet("firewallSubnetTransit", "firewallSubnetTransit",
		"us-south-1", "10.1.15.192/26", vpcTransit)

	transitTestInstance, _ := commonvpc.NewNetworkInterface("transitTestInstance", "transitTestInstance",
		"us-south-1", "10.1.15.4", "transitTestInstanceVSI", 1, false, vpcTransit)
	transitTestInstance2, _ := commonvpc.NewNetworkInterface("transitTestInstance2", "transitTestInstance2",
		"us-south-1", "10.1.15.5", "transitTestInstanceVSI2", 1, false, vpcTransit)
	firewallInstance, _ := commonvpc.NewNetworkInterface("firewallInstance", "firewallInstance",
		"us-south-1", "10.1.15.197", "firewallInstanceVSI", 1, false, vpcTransit)

	spokeTestInstance, _ := commonvpc.NewNetworkInterface("spokeTestInstance", "spokeTestInstance",
		"us-south-1", "10.1.0.4", "spokeTestInstanceVSI", 1, false, vpcSpoke)

	enterpriseTestInstance, _ := commonvpc.NewNetworkInterface("enterpriseTestInstance", "enterpriseTestInstance",
		"z1", "192.168.0.4", "enterpriseTestInstanceVSI", 1, false, vpcEnterprise)

	vpcConfTransit := genConfig(vpcTransit, []*commonvpc.Subnet{workerSubnetTransit, firewallSubnetTransit},
		[]*commonvpc.NetworkInterface{transitTestInstance, transitTestInstance2, firewallInstance}, nil, nil)
	vpcConfSpoke := genConfig(vpcSpoke, []*commonvpc.Subnet{workerSubnetSpoke}, []*commonvpc.NetworkInterface{spokeTestInstance}, nil, nil)
	vpcConfEnterprise := genConfig(vpcEnterprise, []*commonvpc.Subnet{workerSubnetEnterprise},
		[]*commonvpc.NetworkInterface{enterpriseTestInstance}, nil, nil)

	globalConfig := vpcmodel.NewMultipleVPCConfigs(common.IBM)
	globalConfig.AddConfig(vpcConfTransit)
	globalConfig.AddConfig(vpcConfSpoke)
	globalConfig.AddConfig(vpcConfEnterprise)

	// add transit gateways and their generated configs
	tgwSpoke := newTGWForTest("tgwSpoke")
	tgwSpoke.addVPC(vpcSpoke, newTGWConn(), 0)
	tgwSpoke.addVPC(vpcTransit, newTGWConn(), 0)
	vpcConfTransit.RoutingResources = append(vpcConfTransit.RoutingResources, tgwSpoke)
	vpcConfSpoke.RoutingResources = append(vpcConfSpoke.RoutingResources, tgwSpoke)

	tgwLink := newTGWForTest("tgwLink")
	tgwLink.addVPC(vpcEnterprise, newTGWConn(), 0)
	tgwLink.addVPC(vpcTransit, newTGWConn(), 0)
	vpcConfTransit.RoutingResources = append(vpcConfTransit.RoutingResources, tgwLink)
	vpcConfEnterprise.RoutingResources = append(vpcConfEnterprise.RoutingResources, tgwLink)

	addTGWConfig(tgwSpoke, globalConfig)
	addTGWConfig(tgwLink, globalConfig)

	// the implicit ingress routing table may sometimes be sufficient for TGW
	// first case to test: routing based on the implicit RT with TGW
	// two vpcs are involved, thus two RTAnalyzer calls
	// path: (src -> TGW via egress RT) -> (TGW -> dest VPC ->dest  via ingress RT )
	// GlobalRTAnalyzer should be involved to call these analyzers and concatenate the results ...

	// second case: use the defined ingress RT (with advertise:on)

	analyzer := NewGlobalRTAnalyzer(globalConfig)

	return globalConfig, analyzer
}

/*
Ingress routing table:
Zone 		Destination 	Next hop 		Advertise
-----------------------------------------------------
Dallas 1 	192.168.0.0/16 	10.1.15.197 	On
Dallas 1 	10.1.0.0/16 	10.1.15.197 	On
*/

var r1, _ = newRoute("r1", "192.168.0.0/16", "10.1.15.197", "us-south-1", deliver, defaultRoutePriority, true)
var r2, _ = newRoute("r2", "10.1.0.0/16", "10.1.15.197", "us-south-1", deliver, defaultRoutePriority, true)

func newHubSpokeBase2Config() (*vpcmodel.MultipleVPCConfigs, *GlobalRTAnalyzer) {
	globalConfig, _ := newHubSpokeBase1Config()
	transitConfig := globalConfig.Config("transit")
	// define routes of the ingress routing table for transit vpc
	ingressRT := newIngressRoutingTableFromRoutes([]*route{r1, r2}, transitConfig, &vpcmodel.VPCResource{})

	// add ingressRT to transit vpc config
	transitConfig.AddRoutingTable(ingressRT)

	analyzer := NewGlobalRTAnalyzer(globalConfig)
	return globalConfig, analyzer
}

// stop sending traffic destined to the transit VPC to the fw-router: more specific route is added
// to the routing table, to delegate to the default behavior: send directly to the intended destination
// instead of the fw-router
/*
Ingress routing table:
Zone 		Destination 	Next hop 		Advertise  		Action
--------------------------------------------------------------------
Dallas 1 	192.168.0.0/16 	10.1.15.197 	On				deliver
Dallas 1 	10.1.0.0/16 	10.1.15.197 	On				deliver
Dallas 1 	10.1.15.0/24 									delegate
*/

var r3, _ = newRoute("r3", "10.1.15.0/24", "", "us-south-1", delegate, defaultRoutePriority, false)

func newHubSpokeBase3Config() (*vpcmodel.MultipleVPCConfigs, *GlobalRTAnalyzer) {
	globalConfig, _ := newHubSpokeBase1Config()
	transitConfig := globalConfig.Config("transit")
	// define routes of the ingress routing table for transit vpc
	ingressRT := newIngressRoutingTableFromRoutes([]*route{r1, r2, r3}, transitConfig, &vpcmodel.VPCResource{})

	// add ingressRT to transit vpc config
	transitConfig.AddRoutingTable(ingressRT)
	analyzer := NewGlobalRTAnalyzer(globalConfig)
	return globalConfig, analyzer
}

/*
Goal: all traffic between VPCs will flow through the fw-router.
Traffic within a VPC will not flow through the fw-router.

transit Ingress routing table:
Zone 		Destination 	Next hop 		Advertise  		Action
--------------------------------------------------------------------
Dallas 1 	10.1.0.0/16 	10.1.15.197 	On				deliver
Dallas 1 	192.168.0.0/16 	10.1.15.197 	On				deliver

spoke egress routing table:
Zone 		Destination 	Next hop 		  				Action
--------------------------------------------------------------------
Dallas 1 	10.0.0.0/8	 	10.1.15.197 					deliver
Dallas 1	10.1.0.0/24										delegate

transit egress routing table:
Zone 		Destination 	Next hop 		  				Action
--------------------------------------------------------------------
Dallas 1 	10.0.0.0/8	 	10.1.15.197 					deliver
Dallas 1 	192.168.0.0/16 	10.1.15.197 					deliver
Dallas 1	10.1.15.0/24									delegate
*/
var r4, _ = newRoute("r4", "10.0.0.0/8", "10.1.15.197", "us-south-1", deliver, defaultRoutePriority, false)
var r5, _ = newRoute("r5", "192.168.0.0/16", "10.1.15.197", "us-south-1", deliver, defaultRoutePriority, false)
var r6, _ = newRoute("r6", "10.1.15.0/24", "", "us-south-1", delegate, defaultRoutePriority, false)
var r7, _ = newRoute("r7", "10.1.0.0/24", "", "us-south-1", delegate, defaultRoutePriority, false)

func newHubSpokeBase4Config() (*vpcmodel.MultipleVPCConfigs, *GlobalRTAnalyzer) {
	globalConfig, _ := newHubSpokeBase1Config()
	transitConfig := globalConfig.Config("transit")
	// define routes of the ingress routing table for transit vpc
	ingressRT := newIngressRoutingTableFromRoutes([]*route{r1, r2}, transitConfig, &vpcmodel.VPCResource{})
	// add ingressRT to transit vpc config
	transitConfig.AddRoutingTable(ingressRT)

	transitEgressRT := newEgressRoutingTableFromRoutes([]*route{r4, r5, r6},
		getSubnetsByUIDs(transitConfig, []string{"workerSubnetTransit"}), transitConfig, &vpcmodel.VPCResource{})
	transitConfig.AddRoutingTable(transitEgressRT)

	spokeConfig := globalConfig.Config("spoke")
	spokeEgressRT := newEgressRoutingTableFromRoutes([]*route{r4, r5, r7},
		getSubnetsByUIDs(spokeConfig, []string{"workerSubnetSpoke"}), spokeConfig, &vpcmodel.VPCResource{})
	spokeConfig.AddRoutingTable(spokeEgressRT)
	// define routes of the egress routing table for transit vpc

	analyzer := NewGlobalRTAnalyzer(globalConfig)
	return globalConfig, analyzer
}

func getSubnetsByUIDs(config *vpcmodel.VPCConfig, uids []string) (res []*commonvpc.Subnet) {
	for _, s := range config.NodeSets {
		if slices.Contains(uids, s.UID()) {
			res = append(res, s.(*commonvpc.Subnet))
		}
	}
	return res
}

type testGlobalAnalyzer struct {
	src          string
	dst          string
	expectedPath vpcmodel.Path
}

var globalAnalyzerTests = []*testGlobalAnalyzer{
	{
		// simple path within one vpc
		src: "10.1.15.4",
		dst: "10.1.15.5",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance", 1)),
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI2", "10.1.15.5", "transitTestInstance2", 1)),
		),
	},
	{
		// path across 2 vpcs with tgw in between, simple routing (implicit tables only)
		src: "10.1.15.4", // transit vpc
		dst: "10.1.0.4",  // spoke vpc
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwSpoke")),
			vpcmodel.PathFromResource(newNetIntForTest("spokeTestInstanceVSI", "10.1.0.4", "spokeTestInstance", 1)),
		),
		//   NetworkInterface - transitTestInstanceVSI[10.1.15.4] -> TGW - tgwSpoke -> NetworkInterface - spokeTestInstanceVSI[10.1.0.4]
	},
	{
		// src and dst are not connected through the same tgw, thus no path without routing table that adds route advertisement
		src:          "10.1.0.4",    // spoke vpc
		dst:          "192.168.0.4", // enterprise vpc
		expectedPath: nil,
	},
}

/*
Ingress routing table:
Zone 		Destination 	Next hop 		Advertise
-----------------------------------------------------
Dallas 1 	192.168.0.0/16 	10.1.15.197 	On
Dallas 1 	10.1.0.0/16 	10.1.15.197 	On
*/
// test on the above config with route that has advertise=on
// thus, there is a routing path from spoke vpc to enterprise vpc, via the transit-vpc (next hop redirects to firewall-router)
var config2Tests = []*testGlobalAnalyzer{
	{
		// spoke to enterprise part 1 - ends at fw-router
		src: "10.1.0.4",    // spoke vpc
		dst: "192.168.0.4", // enterprise vpc
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("spokeTestInstanceVSI", "10.1.0.4", "spokeTestInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwSpoke")),
			pathFromNextHopValues("10.1.15.197", "192.168.0.4"),
		),
		// NetworkInterface - spokeTestInstanceVSI[10.1.0.4] -> TGW - tgwSpoke -> nextHop: 10.1.15.197 [origDest: 192.168.0.4]
	},
	{
		// spoke to enterprise part 2 - starts fw-router, ends at enterprise
		src: "10.1.15.197",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("firewallInstanceVSI", "10.1.15.197", "firewallInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance", 1)),
		),
		// NetworkInterface - firewallInstanceVSI[10.1.15.197] -> TGW - tgwLink -> NetworkInterface - enterpriseTestInstanceVSI[192.168.0.4]
	},
	{
		// enterprise to transit - part1  - ends at fw-router
		src: "192.168.0.4",
		dst: "10.1.15.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			pathFromNextHopValues("10.1.15.197", "10.1.15.4"),
		),
		// NetworkInterface - enterpriseTestInstanceVSI[192.168.0.4] -> TGW - tgwLink -> nextHop: 10.1.15.197 [origDest: 10.1.15.4]
	},
	{
		// enterprise to transit - part2 -  starts fw-router, ends at transit
		src: "10.1.15.197",
		dst: "10.1.15.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("firewallInstanceVSI", "10.1.15.197", "firewallInstance", 1)),
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance", 1)),
		),
	},
	{
		// response path: transit to enterprise (not symmetric - requires DSR)
		src: "10.1.15.4",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance", 1)),
		),
	},
	{
		// transit to enterprise
		src: "10.1.15.4",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance", 1)),
		),
	},
	{
		//  response path: enterprise to transit - ends at fw-router (not symmetric - DSR will not help)
		// Q: how can this be differentiated from an initiated TCP traffic (as opposed to response) in the analysis,
		// (in the initiated traffic it is expected to get forwarded from fw-router to destination,
		// but in the response case, it is expected to get stuck at the fw-router)
		src: "192.168.0.4",
		dst: "10.1.15.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			pathFromNextHopValues("10.1.15.197", "10.1.15.4"),
		),
	},
}

var config3Tests = []*testGlobalAnalyzer{
	{
		// transit to enterprise
		src: "10.1.15.4",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance", 1)),
		),
	},
	{
		//  response path: enterprise to transit (symmetric path, due to r3 in the ingress routing table-- delegate)
		src: "192.168.0.4",
		dst: "10.1.15.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance", 1)),
		),
	},
	{
		// spoke to enterprise part 1 - ends at fw-router
		src: "10.1.0.4",    // spoke vpc
		dst: "192.168.0.4", // enterprise vpc
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("spokeTestInstanceVSI", "10.1.0.4", "spokeTestInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwSpoke")),
			pathFromNextHopValues("10.1.15.197", "192.168.0.4"),
		),
		// NetworkInterface - spokeTestInstanceVSI[10.1.0.4] -> TGW - tgwSpoke -> nextHop: 10.1.15.197 [origDest: 192.168.0.4]
	},
	{
		// spoke to enterprise part 2 - starts fw-router, ends at enterprise
		src: "10.1.15.197",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("firewallInstanceVSI", "10.1.15.197", "firewallInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance", 1)),
		),
		// NetworkInterface - firewallInstanceVSI[10.1.15.197] -> TGW - tgwLink -> NetworkInterface - enterpriseTestInstanceVSI[192.168.0.4]
	},
}

var config4Tests = []*testGlobalAnalyzer{
	{
		// transit to enterprise - part 1 : ends at fw-router
		src: "10.1.15.4",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance", 1)),
			pathFromNextHopValues("10.1.15.197", "192.168.0.4"),
		),
		// NetworkInterface - transitTestInstanceVSI[10.1.15.4] -> nextHop: 10.1.15.197 [origDest: 192.168.0.4]
	},

	{
		// transit to enterprise - part 2 : starts at fw-router, ends at dest
		src: "10.1.15.197",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("firewallInstanceVSI", "10.1.15.197", "firewallInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance", 1)),
		),
	},

	{
		// response path: enterprise to transit - part1 (symmetric, both paths via the fw-router)
		src: "192.168.0.4",
		dst: "10.1.15.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance", 1)),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			pathFromNextHopValues("10.1.15.197", "10.1.15.4"),
		),
	},

	{
		// response path: enterprise to transit - part2 (symmetric, both paths via the fw-router)
		src: "10.1.15.197",
		dst: "10.1.15.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("firewallInstanceVSI", "10.1.15.197", "firewallInstance", 1)),
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance", 1)),
		),
	},
}

func (tga *testGlobalAnalyzer) run(t *testing.T, globalAnalyzer *GlobalRTAnalyzer, configs *vpcmodel.MultipleVPCConfigs) {
	srcNode, _ := configs.GetInternalNodeFromAddress(tga.src)
	dstIPBlock, _ := ipblock.FromIPAddress(tga.dst)
	path, err := globalAnalyzer.GetRoutingPath(srcNode, dstIPBlock)
	fmt.Printf("path: %s\n", path.String())
	require.Nil(t, err)
	require.True(t, path.Equal(tga.expectedPath))
	fmt.Println("done")
}

func TestTGWRouting(t *testing.T) {
	globalConfig, globalAnalyzer := newHubSpokeBase1Config()
	for _, analyzerTest := range globalAnalyzerTests {
		analyzerTest.run(t, globalAnalyzer, globalConfig)
	}

	// test globalAnalyzer for various routing scenarios
	// start with implicit routing tables
}

func TestTGWRouting2(t *testing.T) {
	globalConfig, globalAnalyzer := newHubSpokeBase2Config()
	for _, analyzerTest := range config2Tests {
		analyzerTest.run(t, globalAnalyzer, globalConfig)
	}
}

func TestTGWRouting3(t *testing.T) {
	globalConfig, globalAnalyzer := newHubSpokeBase3Config()
	for _, analyzerTest := range config3Tests {
		analyzerTest.run(t, globalAnalyzer, globalConfig)
	}
}

func TestTGWRouting4(t *testing.T) {
	globalConfig, globalAnalyzer := newHubSpokeBase4Config()
	for _, analyzerTest := range config4Tests {
		analyzerTest.run(t, globalAnalyzer, globalConfig)
	}
}
