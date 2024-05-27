/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"
	"slices"

	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// GlobalRTAnalyzer analyzes routing in a cross-vpc config
type GlobalRTAnalyzer struct {
	vpcRTAnalyzer map[string]*RTAnalyzer // map from vpc uid to its RTAnalyzer
}

func newGlobalRTAnalyzer(configs *vpcmodel.MultipleVPCConfigs) *GlobalRTAnalyzer {
	res := &GlobalRTAnalyzer{
		vpcRTAnalyzer: map[string]*RTAnalyzer{},
	}
	for vpcUID, vpcConfig := range configs.Configs() {
		if vpcConfig.IsMultipleVPCsConfig {
			continue
		}
		res.vpcRTAnalyzer[vpcUID] = newRTAnalyzer(vpcConfig)
	}
	return res
}

func (ga *GlobalRTAnalyzer) getRTAnalyzerPerVPC(vpcUID string) (*RTAnalyzer, error) {
	rtAnalyzer, ok := ga.vpcRTAnalyzer[vpcUID]
	if !ok {
		return nil, fmt.Errorf("could not find routing analyzer for vpc uid %s", vpcUID)
	}
	return rtAnalyzer, nil
}

func (ga *GlobalRTAnalyzer) getRoutingPath(src vpcmodel.InternalNodeIntf, dest *ipblock.IPBlock) (vpcmodel.Path, error) {
	vpcUID := src.Subnet().VPC().UID()
	rtAnalyzer, err := ga.getRTAnalyzerPerVPC(vpcUID)
	if err != nil {
		return nil, err
	}
	res, err := rtAnalyzer.getEgressPath(src, dest)
	if err != nil {
		return nil, err
	}
	// if res ends with "tgw" -> should get remaining routing path in the target VPC with src:tgw
	if res != nil && res.DoesEndWithTGW() {
		targetVPCAnalyzer, err := ga.getRTAnalyzerPerVPC(res.TargetVPC())
		if err != nil {
			return nil, err
		}
		res2, err := targetVPCAnalyzer.getIngressPath(tgwSource, dest)
		return vpcmodel.ConcatPaths(res, res2), err
	}
	// else - routing remains within a single vpc context
	return res, err
}

// RTAnalyzer analyzes routing in a certain vpc config
type RTAnalyzer struct {
	vpcConfig     *vpcmodel.VPCConfig            // the vpc config
	ingressRT     []*ingressRoutingTable         // the VPC's ingress routing table (one per src type at most?)
	subnetUIDToRT map[string]*egressRoutingTable // the egress routing tables per subnet
	implicitRT    *systemImplicitRT
}

func getRoutingTablesFromConfig(vpcConfig *vpcmodel.VPCConfig) (egressRT []*egressRoutingTable, ingressRT []*ingressRoutingTable) {
	// TODO: extract routing tables from vpc config
	for _, rt := range vpcConfig.RoutingTables {
		switch x := rt.(type) {
		case *egressRoutingTable:
			egressRT = append(egressRT, x)
		case *ingressRoutingTable:
			ingressRT = append(ingressRT, x)
		}
	}
	return egressRT, ingressRT
}

func newRTAnalyzer(vpcConfig *vpcmodel.VPCConfig) *RTAnalyzer {
	egressRT, ingressRT := getRoutingTablesFromConfig(vpcConfig)
	res := &RTAnalyzer{
		vpcConfig:     vpcConfig,
		ingressRT:     ingressRT,
		subnetUIDToRT: map[string]*egressRoutingTable{},
		implicitRT:    newSystemImplicitRT(vpcConfig),
	}

	// add mapping from subnet uid to its routing table
	for _, egressTable := range egressRT {
		for _, subnet := range egressTable.subnets {
			res.subnetUIDToRT[subnet.UID()] = egressTable
		}
	}

	// for each ingress routing table with paths to advertise, propagate these paths
	// currently supporting only tgw advertisement
	for _, ingressTable := range ingressRT {
		ingressTable.advertiseRoutes(vpcConfig)
	}

	return res
}

func (rt *RTAnalyzer) getEgressPathFromAddressSrc(src, dest *ipblock.IPBlock) (vpcmodel.Path, error) {
	for _, node := range rt.vpcConfig.Nodes {
		if node.IsInternal() && node.IPBlock().Equal(src) {
			return rt.getEgressPath(node.(vpcmodel.InternalNodeIntf), dest)
		}
	}
	return nil, fmt.Errorf("could not find internal node with address %s", src.ToIPAddressString())
}

func (rt *RTAnalyzer) getEgressPath(src vpcmodel.InternalNodeIntf, dest *ipblock.IPBlock) (vpcmodel.Path, error) {
	subnet := src.Subnet()
	srcRT, ok := rt.subnetUIDToRT[subnet.UID()]
	if !ok {
		// use the system implicit rt
		// todo: avoid casting here
		return rt.implicitRT.getEgressPath(src.(vpcmodel.Node), dest), nil
	}
	return srcRT.getEgressPath(src.(vpcmodel.Node), dest)
}

func (rt *RTAnalyzer) getIngressPath(sourceType ingressRTSource, dest *ipblock.IPBlock) (vpcmodel.Path, error) {
	for _, ingressRt := range rt.ingressRT {
		if ingressRt.source == sourceType {
			return ingressRt.getIngressPath(dest)
		}
	}
	return rt.implicitRT.getIngressPath(dest)
}

/*
RT features to support:
- priority of routes
- route action: deliver / delegate / drop
- system (implicit) routing table?
- default routing table?


possible queries:
src-> dst : display the route through which it passes (stop at VNF?)
specific subnet/VPC: display the possible routes per disjoint ip-blocks, considering priorities and actions


default routing table:
IBM Cloud® Virtual Private Cloud (VPC) automatically generates a default routing table for the VPC to manage traffic in the zone.
By default, this routing table is empty.
You can add routes to the default routing table, or create one or more custom routing tables and then add routes.
For example, if you want a specialized routing policy for a specific subnet, you can create a routing table and associate
it with one or more subnets.
However, if you want to change the default routing policy that affects all subnets using the default routing table, then you
should add routes to the default routing table.


Q: By default, this routing table is empty. => does this mean the default is "delegate" for all ip ranges?
A: from docs: "the system-implicit routing table is used when no matching route is found in the RT associated with the subnet..."
*/

type action int

const (
	deliver action = iota // Routes the packet to the next hop target.
	// You can add multiple routes with the same address prefix.
	// The virtual router performs equal-cost, multi-path routing (ECMP) by using the different next hop IP addresses.

	delegate // Routes the packet by using the system routing table.

	drop // Drops the packet.

	delegateVPC

	/*
		Delegate-VPC - Delegates to the system's built-in routes, ignoring internet-bound routes. Required if the VPC uses non-RFC-1918 addresses
		 and also has public connectivity
	*/
)

/*
You can control the flow of network traffic in your VPC by configuring routes.
Use VPC routes to specify the next hop for packets, based on their destination addresses.
Multiple routing tables can exist for each zone in your VPC.
For egress traffic, when a packet leaves a subnet, the system evaluates its destination against the routing table in the subnet's zone
to determine where to send the packet next.
Each VPC has a default routing table that will be attached to every subnet (unless it was explicitly
attached to a different one by the user).

A VPC custom route has four main components:
- The destination CIDR
- The next hop where the packet will route (when the action is Deliver) [You can edit the next hop IP address for existing routes]
- The zone
- Action

Any traffic that originates in the specified zone of the VPC and has a destination address within the specified destination
CIDR routes to the next hop.
If the destination address is within the destination CIDR for multiple VPC routes, the most specific route is used.
If the VPC has two or more equally specific routes, the traffic is round-robin that is distributed between each route.

The number of unique prefix lengths that are supported per custom routing table is 14. Multiple routes with the same prefix count
as only one unique prefix.

The Delegate-VPC action is required if both are true:
- The VPC uses non-RFC-1918 addresses
- The VPC has public connectivity
TODO: currently ignoring delegate-vpc action
*/

const (
	defaultRoutePriority int = 2
)

type route struct {
	name string

	// priority - Designate the route priority (0-4) of VPC routes to determine which routes
	// have a higher priority when there are overlapping/multiple routes for a given destination.
	priority int // default priority is 2 (highest - 0)

	action action // The action to perform with a packet that matches the route

	// If a routing table contains multiple routes with the same `zone` and `destination`, the route with the highest
	// priority (smallest value) is selected. If two routes have the same `destination` and `priority`, traffic is
	// distributed between them.
	destination string // cidr -  The destination CIDR of the route (for example, 10.0.0.0/16).

	// The zone the route applies to.
	//
	// If subnets are attached to the route's routing table, egress traffic from those
	// subnets in this zone will be subject to this route. If this route's routing table
	// has any of `route_direct_link_ingress`, `route_internet_ingress`,
	// `route_transit_gateway_ingress` or `route_vpc_zone_ingress`  set to`true`, traffic
	// from those ingress sources arriving in this zone will be subject to this route.
	//nolint:unused // to be used later
	zone string // Select an availability zone for your route.

	// The next-hop-ip for a route must be in the same zone as the zone the traffic is sourcing from
	nextHop string // ip-address (relevant for "deliver") Next hop (IP address)

	// Indicates whether this route will be advertised to the ingress sources specified by the `advertise_routes_to`
	// routing table property.
	/*
		// Constants associated with the RoutingTable.AdvertiseRoutesTo property.
		// An ingress source that routes can be advertised to:
		//
		// - `direct_link` (requires `route_direct_link_ingress` be set to `true`)
		// - `transit_gateway` (requires `route_transit_gateway_ingress` be set to `true`).
	*/
	// sets of routes in a vpc's ingress routing table with advertise=true, will be passed to all transit gateways
	// (same as each vpc connected to a tgw advertises its APs to the tgw )
	advertise bool

	destIPBlock    *ipblock.IPBlock
	nextHopIPBlock *ipblock.IPBlock
	destPrefixLen  int64
}

func newRoute(name, dest, nextHop string, action action, prio int, advertise bool) (res *route, err error) {
	res = &route{
		name:        name,
		destination: dest,
		nextHop:     nextHop,
		action:      action,
		priority:    prio,
		advertise:   advertise,
	}

	res.destIPBlock, err = ipblock.FromCidr(dest)
	if err != nil {
		return nil, err
	}
	res.destPrefixLen, err = res.destIPBlock.PrefixLength()
	if err != nil {
		return nil, err
	}
	if action == deliver { // next hop relevant only for 'deliver' action
		res.nextHopIPBlock, err = ipblock.FromCidrOrAddress(nextHop)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

// routingTable implements VPCResourceIntf (TODO: should implement RoutingResource interface or another separate interface?)
type routingTable struct {
	vpcmodel.VPCResource
	//nolint:unused // to be used later
	name string // should implement VPCResourceIntf instead

	// nextHops is a map from disjoint ip-blocks, after considering route preferences and actions
	nextHops map[*ipblock.IPBlock]*ipblock.IPBlock // delivered ip-blocks

	droppedDestinations *ipblock.IPBlock // union of all ip-ranges for dropped destinations

	delegatedDestinations *ipblock.IPBlock // union of all ip-ranges for delegated destinations

	// routesList is the list of routes that were added for this routing table
	// it is used to compute the fields above
	routesList []*route
	implicitRT *systemImplicitRT
}

func (rt *routingTable) GenerateDrawioTreeNode(gen *vpcmodel.DrawioGenerator) drawio.TreeNodeInterface {
	return nil
}

func (rt *routingTable) ShowOnSubnetMode() bool {
	return false
}

func newRoutingTable(routes []*route, implicitRT *systemImplicitRT) (*routingTable, error) {
	res := &routingTable{routesList: routes}
	if err := res.computeDisjointRouting(); err != nil {
		return nil, err
	}
	res.implicitRT = implicitRT
	return res, nil
}

func (rt *routingTable) computeRoutingForDisjointDest(disjointDest *ipblock.IPBlock) error {
	// find the relevant rule from the sorted list of rules
	for _, routeRule := range rt.routesList {
		if disjointDest.ContainedIn(routeRule.destIPBlock) {
			logging.Debugf("%s contained in %s\n", disjointDest.ToIPRanges(), routeRule.destination)
			switch routeRule.action {
			case deliver:
				rt.nextHops[disjointDest] = routeRule.nextHopIPBlock
				logging.Debugf("set next hop for %s as %s\n", disjointDest.ToIPRanges(), routeRule.nextHop)
				return nil // skip next rules, move to the next disjoint dest
			case drop:
				rt.droppedDestinations = rt.droppedDestinations.Union(disjointDest)
				logging.Debugf("set %s as drop\n", disjointDest.ToIPRanges())
				return nil // skip next rules, move to the next disjoint dest
			case delegate:
				rt.delegatedDestinations = rt.delegatedDestinations.Union(disjointDest)
				logging.Debugf("set %s as delegate\n", disjointDest.ToIPRanges())
				return nil // skip next rules, move to the next disjoint dest
			case delegateVPC:
				return fmt.Errorf("action delegate-vpc is not supported, cannot compute routing")
			}
		}
	}
	return nil
}

// TODO: handle ECMP routing
func (rt *routingTable) computeDisjointRouting() error {
	rt.nextHops = map[*ipblock.IPBlock]*ipblock.IPBlock{}
	rt.droppedDestinations = ipblock.New()
	rt.delegatedDestinations = ipblock.New()
	// sort routes list by prefix length, then by priority
	slices.SortFunc(rt.routesList, func(a, b *route) int {
		if a.destPrefixLen > b.destPrefixLen {
			return -1
		}
		if a.destPrefixLen == b.destPrefixLen && a.priority < b.priority {
			return -1
		}
		return 1
	})

	destIPBlocks := []*ipblock.IPBlock{}
	for _, route := range rt.routesList {
		destIPBlocks = append(destIPBlocks, route.destIPBlock)
	}
	disjointDestinations := ipblock.DisjointIPBlocks(destIPBlocks, destIPBlocks)
	for _, disjointDest := range disjointDestinations {
		logging.Debugf("disjoint dest: %s\n", disjointDest.ToIPRanges())
		if err := rt.computeRoutingForDisjointDest(disjointDest); err != nil {
			return err
		}
	}
	return nil
}

func (rt *routingTable) getEgressPath(src vpcmodel.Node, dest *ipblock.IPBlock) (vpcmodel.Path, error) {
	path, shouldDelegate := rt.getPath(dest)
	if shouldDelegate {
		return rt.implicitRT.getEgressPath(src, dest), nil
	}
	return vpcmodel.ConcatWithResource(src, path), nil
}

func (rt *routingTable) getIngressPath(dest *ipblock.IPBlock) (vpcmodel.Path, error) {
	path, shouldDelegate := rt.getPath(dest)
	if shouldDelegate {
		return rt.implicitRT.getIngressPath(dest)
	}
	return path, nil
}

func (rt *routingTable) getPath(dest *ipblock.IPBlock) (vpcmodel.Path, bool) {
	for tableDest, nextHop := range rt.nextHops {
		if dest.ContainedIn(tableDest) {
			return vpcmodel.Path([]*vpcmodel.Endpoint{
				{NextHop: &vpcmodel.NextHopEntry{NextHop: nextHop, OrigDest: dest}}}), false
		}
	}
	if dest.ContainedIn(rt.delegatedDestinations) {
		// explicit delegate
		return nil, true
	}
	if dest.ContainedIn(rt.droppedDestinations) {
		// explicit drop
		return nil, false // no path
	}
	// implicit delegate: a non-matched destination is delegated to the system-implicit routing table
	return nil, true
}

type ingressRTSource int

const (
	// one ingress routing table to all source of kind TGW (even if VPC has more han one TGW)
	tgwSource ingressRTSource = iota

	// direct link source
	//nolint:unused // to be used later
	dlSource

	// public internet source
	//nolint:unused // to be used later
	publicInternetSource

	// other zone source
	//nolint:unused // to be used later
	otherZoneSource
)

func newIngressRoutingTableFromRoutes(routes []*route, vpcConfig *vpcmodel.VPCConfig) *ingressRoutingTable {
	routingTable, _ := newRoutingTable(routes, newSystemImplicitRT(vpcConfig))
	return &ingressRoutingTable{
		vpc:          vpcConfig.VPC.(*VPC),
		source:       tgwSource, // todo: support more sources to ingress RT
		routingTable: *routingTable,
	}
}

/*
ingress routes enables you to customize routes on incoming traffic to a VPC from traffic sources external to the VPC's zone
(Direct Link, Transit Gateway, another availability zone in the same vpc, or the public internet)
*/

type ingressRoutingTable struct {
	routingTable
	vpc    *VPC
	source ingressRTSource // TGW / DL / public internet (ALB/CIS?) / another zone in the same vpc / 3-rd party appliance?
	/*
		source info:
		Traffic source (optional) - Select the traffic source that will use this routing table to route its traffic to the VPC.
		- Public internet - Allows public internet ingress traffic destined to a floating IP to be routed to a VPC next-hop IP.
		- VPC zone - Allows ingress traffic to another availability zone of the same VPC.
		- Transit gateway - Allows ingress traffic from an IBM Cloud Transit Gateway to another VPC or classic infrastructure.
							Optionally, you can advertise routes to a transit gateway, which are not in the address prefix range of the VPC.
		- Direct Link - Allows ingress traffic from an IBM Cloud Direct Link Dedicated or Connect connection to an on-premises location.
							Optionally, you can advertise routes to a direct link, which are not in the address prefix range of the VPC.

	*/
}

// if a vpc `A` has ingress routing table, having a dest cidr `Y` with `advertise=On`,
// (with src:tgw in the routing table, and vpc: `B` contains AP that contains `Y`) should consider
// all its `A`'s other tgws ( for example: tgw connecting `A` with other VPC: `C`) [which are not
// connected to the  VPC containing this dest cidr in their APs], and add to them this advertised prefix
// (with VPC connected to this tgw and the other tgw)  for example, `C-A` tgw should be added with available
// prefix `Y`, under `vpc-A` prefixes, even though `A` does not have this cidr. this way, `C` can route to `A`
// if the dest is in `B`, and from A can route to `B` through the other TGW, and based on the ingress routing table.

func (irt *ingressRoutingTable) advertiseRoutes(vpcConfig *vpcmodel.VPCConfig) {
	if irt.source != tgwSource {
		return // currently supporting only tgw source for routes advertisement
	}
	for _, routeObj := range irt.routesList {
		if !routeObj.advertise {
			continue
		}

		routeCidr := routeObj.destIPBlock
		tgws := getTGWs(vpcConfig)
		if len(tgws) <= 1 {
			break // nothing to propagate if there is only one TGW connected to this vpc
		}
		// find the vpc (with tgw) to which this cidr Y belongs
		var vpcB *VPC
		var tgwAB *TransitGateway
		for _, tgw := range tgws {
			for _, vpc := range tgw.vpcs {
				if routeCidr.ContainedIn(vpc.addressPrefixesIPBlock) && vpc.UID() != irt.vpc.UID() {
					vpcB = vpc
					tgwAB = tgw
					break
				}
			}
		}
		if vpcB == nil {
			break // nothing to propagate if could not find the relevant vpc and its tgw
		}
		// find other tgws connected to this VPC (of irt) and
		// propagate this cidr Y to the available routes from this VPC to those tgws
		var tgwAC *TransitGateway
		for _, tgw := range tgws {
			if tgw.UID() == tgwAB.UID() {
				continue
			}
			if slices.Contains(tgw.vpcs, vpcB) {
				continue // skip any tgw that already has available prefixes from vpc B
			}
			tgwAC = tgw // the tgw A-C to which should propagate Y (routeCidr) as available "from" vpcA
			updateTGWWithAdvertisedRoute(tgwAC, irt.vpc, routeCidr)
		}
	}
}

func updateTGWWithAdvertisedRoute(tgw *TransitGateway, vpc *VPC, cidr *ipblock.IPBlock) {
	_, ok := tgw.availableRoutes[vpc.UID()]
	if !ok {
		tgw.availableRoutes[vpc.UID()] = []*ipblock.IPBlock{}
	}
	tgw.availableRoutes[vpc.UID()] = append(tgw.availableRoutes[vpc.UID()], cidr)
}

func getTGWs(vpcConfig *vpcmodel.VPCConfig) (res []*TransitGateway) {
	for _, router := range vpcConfig.RoutingResources {
		if router.Kind() == ResourceTypeTGW {
			res = append(res, router.(*TransitGateway))
		}
	}
	return res
}

/*
Egress routes control traffic, which originates within a subnet and travels towards the public internet,
or to another VM in same or different zone.
*/
type egressRoutingTable struct {
	routingTable
	subnets []*Subnet
	vpc     *VPC
}

func newEgressRoutingTableFromRoutes(routes []*route, subnets []*Subnet, vpcConfig *vpcmodel.VPCConfig) *egressRoutingTable {
	routingTable, _ := newRoutingTable(routes, newSystemImplicitRT(vpcConfig))
	return &egressRoutingTable{
		routingTable: *routingTable,
		subnets:      subnets,
		vpc:          vpcConfig.VPC.(*VPC),
	}
}

/*
func newEgressRTFromRoutes(rps *routesPerSubnets, config *vpcmodel.VPCConfig, vpc *VPC) []*egressRoutingTable {
	res := []*egressRoutingTable{}
	for subnetsKey, routes := range rps.routesMap {
		egressRT := &egressRoutingTable{}
		implicitRT := &systemImplicitRT{vpc: vpc, config: systemRTConfigFromVPCConfig(config)}
		if rt, err := newRoutingTable(routes, implicitRT); err == nil {
			egressRT.routingTable = *rt
		}
		egressRT.vpc = vpc
		egressRT.subnets = subnetsKeyToSubnets(subnetsKey, config)
		res = append(res, egressRT)
	}
	return res
}
*/

///////////////////////////////////////////////////////////////////////////////////////////////////////////
