package ibmvpc

import (
	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

/*
The system-implicit routing table contains:
    Routes to the CIDR of each subnet in the VPC
    Routes to subnets within the zone (statically maintained)
    Routes to subnets in other zones that are learned through BGP
    Dynamic routes learned through BGP (for example, Direct Link and Transit Gateway)
    The default route for internet traffic (used when a public gateway or floating IP is associated with the VPC)
    Routes to the classic infrastructure service network CIDRs (used when a service gateway is associated with the VPC)
*/

// system implicit routing table - maintained for each VPC
/*
	A system-implicit routing table is maintained for each VPC.
	A VPC can have a presence in multiple zones, and the VPC's system-implicit routing table is different in each zone.
	For ingress routing, the system-implicit routing table contains only routes to each network interface in the VPC’s zone.
*/

/*
You cannot configure a routing table to use the system-implicit routing table; it is populated automatically.
The system-implicit routing table is used when no matching route is found in the custom routing table that is
associated with the subnet where the traffic is egressing.
If no match is found, the packet is dropped.

This behavior can be avoided with a custom routing table default route with an action of drop.
*/
type systemImplicitRT struct {
	vpc    *VPC // parent VPC
	config *systemRTConfig
	// TODO: should be per zone in vpc
}

type systemRTConfig struct {
	tgwList []*TransitGateway
	fipList []*FloatingIP
	pgwList []*PublicGateway
}

func isDestPublicInternet(dest *ipblock.IPBlock) bool {
	_, publicRange, _ := vpcmodel.GetPublicInternetIPblocksList()
	return dest.ContainedIn(publicRange)
}

func fipHasSource(src vpcmodel.Node, fip *FloatingIP) bool {
	for _, fipNode := range fip.src {
		if fipNode.UID() == src.UID() {
			return true
		}
	}
	return false
}

func pgwHasSource(src vpcmodel.Node, pgw *PublicGateway) bool {
	cidrs, _ := ipblock.FromCidrList(pgw.subnetCidr)
	return src.IPBlock().ContainedIn(cidrs)
	// another option: compare by nodes within pgw.src (currently breaks test)
}

// getPath returns a path from src to dst if such exists, or nil otherwise
// TODO: src should be InternalNodeIntf, but it does not implement VPCResourceIntf
func (rt *systemImplicitRT) getPath(src vpcmodel.Node, dest *ipblock.IPBlock) vpcmodel.Path {
	// TODO: split dest by disjoint ip-blocks of the vpc-config (the known destinations ip-blocks)

	if dest.ContainedIn(rt.vpc.addressPrefixesIPBlock) {
		// direct connection
		return []*vpcmodel.Endpoint{{VpcResource: src}, {IPBlock: dest}}
	}

	if isDestPublicInternet(dest) {
		for _, fip := range rt.config.fipList {
			if fipHasSource(src, fip) {
				// path through fip
				return []*vpcmodel.Endpoint{{VpcResource: src}, {VpcResource: fip}, {IPBlock: dest}}
			}
		}
		for _, pgw := range rt.config.pgwList {
			if pgwHasSource(src, pgw) {
				// path through pgw
				return []*vpcmodel.Endpoint{{VpcResource: src}, {VpcResource: pgw}, {IPBlock: dest}}
			}
		}
		// no path to public internet from src node
		return nil
	}

	for _, tgw := range rt.config.tgwList {
		for vpcUID, availablePrefixes := range tgw.availableRoutes {
			if vpcUID == rt.vpc.ResourceUID {
				continue
			}
			// TODO: what if dest is within available prefix of another vpc, but there is no such subnet?
			// This is actually concatenation of paths from 2 vpcs RT's : for the source, the egress RT that directs to TGW
			// and in the dest VPC, the ingress RT  that directs to subnets within the VPC
			/*
				A system-implicit routing table is maintained for each VPC.
				A VPC can have a presence in multiple zones, and the VPC's system-implicit routing table is different in each zone.
				For ingress routing, the system-implicit routing table contains only routes to each network interface in the VPC’s zone.
			*/
			// could fail on multiple points: (1) if no matching TGW found (2) if the dest VPC has no matching subnet and network interface
			// (the dest VPC could publish its AddressPrefix, but may not have the required dest subnet )
			for _, prefix := range availablePrefixes {
				if dest.ContainedIn(prefix) {
					// path through tgw
					return []*vpcmodel.Endpoint{{VpcResource: src}, {VpcResource: tgw}, {IPBlock: dest}}
				}
			}
		}
	}
	/*
			TODO: not fully handled:
			- Dynamic routes learned through BGP (for example, Direct Link and Transit Gateway)
		    - Routes to the classic infrastructure service network CIDRs (used when a service gateway is associated with the VPC)
			- service network?
	*/

	return nil
}
