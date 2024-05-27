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

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/ipblock"
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
	return newTGW(name, name, "", map[string]*Region{}, nil)
}

func addTGWConfig(tgwObj *TransitGateway, configs *vpcmodel.MultipleVPCConfigs) {
	tgwConfig, _ := tgwObj.newConfigFromTGW(configs)
	configs.AddConfig(tgwConfig)
}

func newHubSpokeBase1Config() (*vpcmodel.MultipleVPCConfigs, *GlobalRTAnalyzer) {
	vpcTransit, _ := newVPC("transit", "transit", "", []string{"10.1.15.0/24"}, map[string]*Region{})
	vpcSpoke, _ := newVPC("spoke", "spoke", "", []string{"10.1.0.0/24"}, map[string]*Region{})
	vpcEnterprise, _ := newVPC("enterprise", "enterprise", "", []string{"192.168.0.0/16"}, map[string]*Region{})

	workerSubnetTransit, _ := newSubnet("workerSubnetTransit", "workerSubnetTransit", "zone1", "10.1.15.0/26", vpcTransit)
	workerSubnetSpoke, _ := newSubnet("workerSubnetSpoke", "workerSubnetSpoke", "zone1", "10.1.0.0/26", vpcSpoke)
	workerSubnetEnterprise, _ := newSubnet("workerSubnetEnterprise", "workerSubnetEnterprise", "zone1", "192.168.0.0/16", vpcEnterprise)
	firewallSubnetTransit, _ := newSubnet("firewallSubnetTransit", "firewallSubnetTransit", "zone1", "10.1.15.192/26", vpcTransit)

	transitTestInstance, _ := newNetworkInterface("transitTestInstance", "transitTestInstance",
		"zone1", "10.1.15.4", "transitTestInstanceVSI", vpcTransit)
	transitTestInstance2, _ := newNetworkInterface("transitTestInstance2", "transitTestInstance2",
		"zone1", "10.1.15.5", "transitTestInstanceVSI2", vpcTransit)
	firewallInstance, _ := newNetworkInterface("firewallInstance", "firewallInstance",
		"zone1", "10.1.15.197", "firewallInstanceVSI", vpcTransit)

	spokeTestInstance, _ := newNetworkInterface("spokeTestInstance", "spokeTestInstance",
		"zone1", "10.1.0.4", "spokeTestInstanceVSI", vpcSpoke)

	enterpriseTestInstance, _ := newNetworkInterface("enterpriseTestInstance", "enterpriseTestInstance",
		"zone1", "192.168.0.4", "enterpriseTestInstanceVSI", vpcEnterprise)

	vpcConfTransit := genConfig(vpcTransit, []*Subnet{workerSubnetTransit, firewallSubnetTransit},
		[]*NetworkInterface{transitTestInstance, transitTestInstance2, firewallInstance}, nil, nil)
	vpcConfSpoke := genConfig(vpcSpoke, []*Subnet{workerSubnetSpoke}, []*NetworkInterface{spokeTestInstance}, nil, nil)
	vpcConfEnterprise := genConfig(vpcEnterprise, []*Subnet{workerSubnetEnterprise}, []*NetworkInterface{enterpriseTestInstance}, nil, nil)

	globalConfig := vpcmodel.NewMultipleVPCConfigs("")
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

	analyzer := newGlobalRTAnalyzer(globalConfig)

	return globalConfig, analyzer
}

/*
Ingress routing table:
Zone 		Destination 	Next hop 		Advertise
-----------------------------------------------------
Dallas 1 	192.168.0.0/16 	10.1.15.197 	On
Dallas 1 	10.1.0.0/16 	10.1.15.197 	On
*/

var r1, _ = newRoute("r1", "192.168.0.0/16", "10.1.15.197", deliver, defaultRoutePriority, true)
var r2, _ = newRoute("r2", "10.1.0.0/16", "10.1.15.197", deliver, defaultRoutePriority, true)

func newHubSpokeBase2Config() (*vpcmodel.MultipleVPCConfigs, *GlobalRTAnalyzer) {
	globalConfig, _ := newHubSpokeBase1Config()
	transitConfig := globalConfig.GetVPCConfig("transit")
	// define routes of the ingress routing table for transit vpc
	ingressRT := newIngressRoutingTableFromRoutes([]*route{r1, r2}, transitConfig)

	// add ingressRT to transit vpc config
	transitConfig.AddRoutingTable(ingressRT)

	analyzer := newGlobalRTAnalyzer(globalConfig)
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

var r3, _ = newRoute("r3", "10.1.15.0/24", "", delegate, defaultRoutePriority, false)

func newHubSpokeBase3Config() (*vpcmodel.MultipleVPCConfigs, *GlobalRTAnalyzer) {
	globalConfig, _ := newHubSpokeBase1Config()
	transitConfig := globalConfig.GetVPCConfig("transit")
	// define routes of the ingress routing table for transit vpc
	ingressRT := newIngressRoutingTableFromRoutes([]*route{r1, r2, r3}, transitConfig)

	// add ingressRT to transit vpc config
	transitConfig.AddRoutingTable(ingressRT)
	analyzer := newGlobalRTAnalyzer(globalConfig)
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
var r4, _ = newRoute("r4", "10.0.0.0/8", "10.1.15.197", deliver, defaultRoutePriority, false)
var r5, _ = newRoute("r5", "192.168.0.0/16", "10.1.15.197", deliver, defaultRoutePriority, false)
var r6, _ = newRoute("r6", "10.1.15.0/24", "", delegate, defaultRoutePriority, false)
var r7, _ = newRoute("r7", "10.1.0.0/24", "", delegate, defaultRoutePriority, false)

func newHubSpokeBase4Config() (*vpcmodel.MultipleVPCConfigs, *GlobalRTAnalyzer) {
	globalConfig, _ := newHubSpokeBase1Config()
	transitConfig := globalConfig.GetVPCConfig("transit")
	// define routes of the ingress routing table for transit vpc
	ingressRT := newIngressRoutingTableFromRoutes([]*route{r1, r2}, transitConfig)
	// add ingressRT to transit vpc config
	transitConfig.AddRoutingTable(ingressRT)

	transitEgressRT := newEgressRoutingTableFromRoutes([]*route{r4, r5, r6},
		getSubnetsByUIDs(transitConfig, []string{"workerSubnetTransit"}), transitConfig)
	transitConfig.AddRoutingTable(transitEgressRT)

	spokeConfig := globalConfig.GetVPCConfig("spoke")
	spokeEgressRT := newEgressRoutingTableFromRoutes([]*route{r4, r5, r7},
		getSubnetsByUIDs(spokeConfig, []string{"workerSubnetSpoke"}), spokeConfig)
	spokeConfig.AddRoutingTable(spokeEgressRT)
	// define routes of the egress routing table for transit vpc

	analyzer := newGlobalRTAnalyzer(globalConfig)
	return globalConfig, analyzer
}

func getSubnetsByUIDs(config *vpcmodel.VPCConfig, uids []string) (res []*Subnet) {
	for _, s := range config.NodeSets {
		if slices.Contains(uids, s.UID()) {
			res = append(res, s.(*Subnet))
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
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance")),
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI2", "10.1.15.5", "transitTestInstance2")),
		),
	},
	{
		// path across 2 vpcs with tgw in between, simple routing (implicit tables only)
		src: "10.1.15.4", // transit vpc
		dst: "10.1.0.4",  // spoke vpc
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwSpoke")),
			vpcmodel.PathFromResource(newNetIntForTest("spokeTestInstanceVSI", "10.1.0.4", "spokeTestInstance")),
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
			vpcmodel.PathFromResource(newNetIntForTest("spokeTestInstanceVSI", "10.1.0.4", "spokeTestInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwSpoke")),
			vpcmodel.PathFromNextHopValues("10.1.15.197", "192.168.0.4"),
		),
		// NetworkInterface - spokeTestInstanceVSI[10.1.0.4] -> TGW - tgwSpoke -> nextHop: 10.1.15.197 [origDest: 192.168.0.4]
	},
	{
		// spoke to enterprise part 2 - starts fw-router, ends at enterprise
		src: "10.1.15.197",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("firewallInstanceVSI", "10.1.15.197", "firewallInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance")),
		),
		// NetworkInterface - firewallInstanceVSI[10.1.15.197] -> TGW - tgwLink -> NetworkInterface - enterpriseTestInstanceVSI[192.168.0.4]
	},
	{
		// enterprise to transit - part1  - ends at fw-router
		src: "192.168.0.4",
		dst: "10.1.15.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromNextHopValues("10.1.15.197", "10.1.15.4"),
		),
		// NetworkInterface - enterpriseTestInstanceVSI[192.168.0.4] -> TGW - tgwLink -> nextHop: 10.1.15.197 [origDest: 10.1.15.4]
	},
	{
		// enterprise to transit - part2 -  starts fw-router, ends at transit
		src: "10.1.15.197",
		dst: "10.1.15.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("firewallInstanceVSI", "10.1.15.197", "firewallInstance")),
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance")),
		),
	},
	{
		// response path: transit to enterprise (not symmetric - requires DSR)
		src: "10.1.15.4",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance")),
		),
	},
	{
		// transit to enterprise
		src: "10.1.15.4",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance")),
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
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromNextHopValues("10.1.15.197", "10.1.15.4"),
		),
	},
}

var config3Tests = []*testGlobalAnalyzer{
	{
		// transit to enterprise
		src: "10.1.15.4",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance")),
		),
	},
	{
		//  response path: enterprise to transit (symmetric path, due to r3 in the ingress routing table-- delegate)
		src: "192.168.0.4",
		dst: "10.1.15.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance")),
		),
	},
	{
		// spoke to enterprise part 1 - ends at fw-router
		src: "10.1.0.4",    // spoke vpc
		dst: "192.168.0.4", // enterprise vpc
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("spokeTestInstanceVSI", "10.1.0.4", "spokeTestInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwSpoke")),
			vpcmodel.PathFromNextHopValues("10.1.15.197", "192.168.0.4"),
		),
		// NetworkInterface - spokeTestInstanceVSI[10.1.0.4] -> TGW - tgwSpoke -> nextHop: 10.1.15.197 [origDest: 192.168.0.4]
	},
	{
		// spoke to enterprise part 2 - starts fw-router, ends at enterprise
		src: "10.1.15.197",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("firewallInstanceVSI", "10.1.15.197", "firewallInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance")),
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
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance")),
			vpcmodel.PathFromNextHopValues("10.1.15.197", "192.168.0.4"),
		),
		// NetworkInterface - transitTestInstanceVSI[10.1.15.4] -> nextHop: 10.1.15.197 [origDest: 192.168.0.4]
	},

	{
		// transit to enterprise - part 2 : starts at fw-router, ends at dest
		src: "10.1.15.197",
		dst: "192.168.0.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("firewallInstanceVSI", "10.1.15.197", "firewallInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance")),
		),
	},

	{
		// response path: enterprise to transit - part1 (symmetric, both paths via the fw-router)
		src: "192.168.0.4",
		dst: "10.1.15.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("enterpriseTestInstanceVSI", "192.168.0.4", "enterpriseTestInstance")),
			vpcmodel.PathFromResource(newTGWForTest("tgwLink")),
			vpcmodel.PathFromNextHopValues("10.1.15.197", "10.1.15.4"),
		),
	},

	{
		// response path: enterprise to transit - part2 (symmetric, both paths via the fw-router)
		src: "10.1.15.197",
		dst: "10.1.15.4",
		expectedPath: vpcmodel.ConcatPaths(
			vpcmodel.PathFromResource(newNetIntForTest("firewallInstanceVSI", "10.1.15.197", "firewallInstance")),
			vpcmodel.PathFromResource(newNetIntForTest("transitTestInstanceVSI", "10.1.15.4", "transitTestInstance")),
		),
	},
}

func (tga *testGlobalAnalyzer) run(t *testing.T, globalAnalyzer *GlobalRTAnalyzer, configs *vpcmodel.MultipleVPCConfigs) {
	srcNode, _ := configs.GetInternalNodeFromAddress(tga.src)
	dstIPBlock, _ := ipblock.FromIPAddress(tga.dst)
	path, err := globalAnalyzer.getRoutingPath(srcNode, dstIPBlock)
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
