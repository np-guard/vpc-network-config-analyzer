package ibmvpc

import (
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// RTAnalyzer analyzes routing in a certain vpc config
type RTAnalyzer struct {
	vpcConfig     *vpcmodel.VPCConfig
	egressRT      []*egressRoutingTable
	ingressRT     *ingressRoutingTable
	subnetUIDToRT map[string]*egressRoutingTable
}

func newRTAnalyzer(vpcConfig *vpcmodel.VPCConfig, egressRT []*egressRoutingTable, ingressRT *ingressRoutingTable) *RTAnalyzer {
	res := &RTAnalyzer{
		vpcConfig:     vpcConfig,
		egressRT:      egressRT,
		ingressRT:     ingressRT,
		subnetUIDToRT: map[string]*egressRoutingTable{},
	}

	// add mapping from subnet uid to its routing table
	for _, egressTable := range egressRT {
		for _, subnet := range egressTable.subnets {
			res.subnetUIDToRT[subnet.UID()] = egressTable
		}
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
		return nil, fmt.Errorf("could not find routing table for subnet %s", subnet.Name())
	}
	return srcRT.getPath(src.(vpcmodel.Node), dest), nil
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

questions:
By default, this routing table is empty. => does this mean the default is "delegate" for all ip ranges?
*/

type action int

const (
	deliver action = iota // Routes the packet to the next hop target.
	// You can add multiple routes with the same address prefix.
	// The virtual router performs equal-cost, multi-path routing (ECMP) by using the different next hop IP addresses.

	delegate // Routes the packet by using the system routing table.

	drop // Drops the packet.

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
type route struct {
	name string

	// priority - Designate the route priority (0-4) of VPC routes to determine which routes
	// have a higher priority when there are overlapping/multiple routes for a given destination.
	priority int // default priority is 2 (highest - 0)

	action action // The action to perform with a packet that matches the route

	destination string // cidr -  The destination CIDR of the route (for example, 10.0.0.0/16).

	//nolint:unused // to be used later
	zone string // Select an availability zone for your route.

	// The next-hop-ip for a route must be in the same zone as the zone the traffic is sourcing from
	nextHop string // ip-address (relevant for "deliver") Next hop (IP address)

	destIPBlock    *ipblock.IPBlock
	nextHopIPBlock *ipblock.IPBlock
	destPrefixLen  int64
}

func newRoute(name, dest, nextHop string, action action, prio int) (res *route) {
	res = &route{
		name:        name,
		destination: dest,
		nextHop:     nextHop,
		action:      action,
		priority:    prio,
	}

	var err error
	res.destIPBlock, err = ipblock.FromCidr(dest)
	if err != nil {
		log.Panicf("invalid dest CIDR: %e", err)
	}
	res.destPrefixLen, err = res.destIPBlock.PrefixLength()
	if err != nil {
		log.Panicf("PrefixLength err: %e", err)
	}
	if action == deliver { // next hop relevant only for 'deliver' action
		res.nextHopIPBlock, err = ipblock.FromCidrOrAddress(nextHop)
		if err != nil {
			log.Panicf("invalid next-hop CIDR: %e", err)
		}
	}

	return res
}

func configFromVPCConfig(vpcConfig *vpcmodel.VPCConfig) *systemRTConfig {
	res := &systemRTConfig{}
	for _, router := range vpcConfig.RoutingResources {
		switch router.Kind() {
		case ResourceTypeTGW:
			res.tgwList = append(res.tgwList, router.(*TransitGateway))
		case ResourceTypePublicGateway:
			res.pgwList = append(res.pgwList, router.(*PublicGateway))
		case ResourceTypeFloatingIP:
			res.fipList = append(res.fipList, router.(*FloatingIP))
		}
	}
	return res
}

func newRoutingTable(routes []*route, vpcConfig *vpcmodel.VPCConfig, vpc *VPC) *routingTable {
	if vpcConfig == nil {
		vpcConfig = &vpcmodel.VPCConfig{}
	}
	res := &routingTable{routesList: routes}
	res.computeDisjointRouting()
	res.implicitRT = &systemImplicitRT{vpc: vpc, config: configFromVPCConfig(vpcConfig)}
	return res
}

type routingTable struct {
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

func (rt *routingTable) disjointRoutingStr() string {
	lines := []string{}
	for dest, nextHop := range rt.nextHops {
		lines = append(lines, fmt.Sprintf("%s -> %s", dest.ToIPRanges(), nextHop.ToIPAddressString()))
	}
	for _, droppedDest := range rt.droppedDestinations.ToCidrList() {
		lines = append(lines, fmt.Sprintf("%s -> drop", droppedDest))
	}
	for _, delegatedDest := range rt.delegatedDestinations.ToCidrList() {
		lines = append(lines, fmt.Sprintf("%s -> delegate", delegatedDest))
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

func (rt *routingTable) computeRoutingForDisjointDest(disjointDest *ipblock.IPBlock) {
	// find the relevant rule from the sorted list of rules
	for _, routeRule := range rt.routesList {
		if disjointDest.ContainedIn(routeRule.destIPBlock) {
			log.Default().Printf("%s contained in %s\n", disjointDest.ToIPRanges(), routeRule.destination)
			switch routeRule.action {
			case deliver:
				rt.nextHops[disjointDest] = routeRule.nextHopIPBlock
				log.Default().Printf("set next hop for %s as %s\n", disjointDest.ToIPRanges(), routeRule.nextHop)
				return // skip next rules, move to the next disjoint dest
			case drop:
				rt.droppedDestinations = rt.droppedDestinations.Union(disjointDest)
				log.Default().Printf("set %s as drop\n", disjointDest.ToIPRanges())
				return // skip next rules, move to the next disjoint dest
			case delegate:
				rt.delegatedDestinations = rt.delegatedDestinations.Union(disjointDest)
				log.Default().Printf("set %s as delegate\n", disjointDest.ToIPRanges())
				return // skip next rules, move to the next disjoint dest
			}
		}
	}
}

func (rt *routingTable) getPath(src vpcmodel.Node, dest *ipblock.IPBlock) vpcmodel.Path {
	for tableDest, nextHop := range rt.nextHops {
		if dest.ContainedIn(tableDest) {
			return vpcmodel.Path([]*vpcmodel.Endpoint{
				{VpcResource: src},
				{NextHop: &vpcmodel.NextHopEntry{NextHop: nextHop, OrigDest: dest}}})
		}
	}
	if dest.ContainedIn(rt.delegatedDestinations) {
		// explicit delegate
		return rt.implicitRT.getPath(src, dest)
	}
	if dest.ContainedIn(rt.droppedDestinations) {
		// explicit drop
		return nil // no path
	}
	// implicit delegate
	return rt.implicitRT.getPath(src, dest)
}

// TODO: handle ECMP routing
func (rt *routingTable) computeDisjointRouting() {
	rt.nextHops = map[*ipblock.IPBlock]*ipblock.IPBlock{}
	rt.droppedDestinations = ipblock.New()
	rt.delegatedDestinations = ipblock.New()
	// sort routes list by prefix length, then by priority
	sort.Slice(rt.routesList, func(i, j int) bool {
		if rt.routesList[i].destPrefixLen > rt.routesList[j].destPrefixLen {
			return true
		}
		if rt.routesList[i].destPrefixLen == rt.routesList[j].destPrefixLen {
			return rt.routesList[i].priority < rt.routesList[j].priority
		}
		return false
	})
	destIPBlocks := []*ipblock.IPBlock{}
	for _, route := range rt.routesList {
		destIPBlocks = append(destIPBlocks, route.destIPBlock)
	}
	disjointDestinations := ipblock.DisjointIPBlocks(destIPBlocks, destIPBlocks)
	for _, disjointDest := range disjointDestinations {
		log.Default().Printf("disjoint dest: %s\n", disjointDest.ToIPRanges())
		rt.computeRoutingForDisjointDest(disjointDest)
	}
}

/*
ingress routes enables you to customize routes on incoming traffic to a VPC from traffic sources external to the VPC's zone
(Direct Link, Transit Gateway, another availability zone in the same vpc, or the public internet)
*/
//nolint:unused // to be used later
type ingressRoutingTable struct {
	routingTable
	vpc    *VPC
	source *vpcmodel.VPCResourceIntf // TGW / DL / public internet (ALB/CIS?) / another zone in the same vpc / 3-rd party appliance?
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

/*
Egress routes control traffic, which originates within a subnet and travels towards the public internet,
or to another VM in same or different zone.
*/
type egressRoutingTable struct {
	routingTable // TODO: a non-matched destination is delegated to the system-implicit routing table
	subnets      []*Subnet
	vpc          *VPC
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////
