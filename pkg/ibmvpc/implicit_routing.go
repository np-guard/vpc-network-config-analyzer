/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"fmt"

	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
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
	vpc       *commonvpc.VPC // parent VPC
	config    *systemRTConfig
	vpcConfig *vpcmodel.VPCConfig
	// TODO: should be per zone in vpc
}

func newSystemImplicitRT(vpcConfig *vpcmodel.VPCConfig) *systemImplicitRT {
	return &systemImplicitRT{
		// todo: add method getVPC() for vpcConfig instead of casting types here
		vpc:       (vpcConfig.VPC).(*commonvpc.VPC),
		config:    systemRTConfigFromVPCConfig(vpcConfig),
		vpcConfig: vpcConfig,
	}
}

type systemRTConfig struct {
	tgwList []*TransitGateway
	fipList []*FloatingIP
	pgwList []*PublicGateway
}

func (rt *systemImplicitRT) destAsPath(dest *ipblock.IPBlock) vpcmodel.Path {
	internalNodes := rt.vpcConfig.GetNodesWithinInternalAddress(dest)
	if len(internalNodes) != 1 {
		// TODO: add error handling here?
		return nil
	}
	return vpcmodel.PathFromResource(internalNodes[0])
}

func systemRTConfigFromVPCConfig(vpcConfig *vpcmodel.VPCConfig) *systemRTConfig {
	res := &systemRTConfig{}
	for _, router := range vpcConfig.RoutingResources {
		switch router.Kind() {
		case commonvpc.ResourceTypeTGW:
			res.tgwList = append(res.tgwList, router.(*TransitGateway))
		case commonvpc.ResourceTypePublicGateway:
			res.pgwList = append(res.pgwList, router.(*PublicGateway))
		case commonvpc.ResourceTypeFloatingIP:
			res.fipList = append(res.fipList, router.(*FloatingIP))
		}
	}
	return res
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

// getIngressPath returns a path to dest
func (rt *systemImplicitRT) getIngressPath(dest *ipblock.IPBlock) (vpcmodel.Path, error) {
	// traffic from some source is by default simply routed to dest node
	path := rt.destAsPath(dest)
	if len(path) == 0 {
		return nil, fmt.Errorf("getIngressPath: failed to find path to dest resource address %s in VPC %s",
			dest.String(), rt.vpc.NameForAnalyzerOut())
	}
	return path, nil
}

// getEgressPath returns a path from src to dst if such exists, or nil otherwise
// TODO: src should be InternalNodeIntf, but it does not implement VPCResourceIntf
func (rt *systemImplicitRT) getEgressPath(src vpcmodel.Node, dest *ipblock.IPBlock) vpcmodel.Path {
	// TODO: split dest by disjoint ip-blocks of the vpc-config (the known destinations ip-blocks)

	if dest.ContainedIn(rt.vpc.AddressPrefixes()) {
		// direct connection
		return vpcmodel.ConcatPaths(vpcmodel.PathFromResource(src), rt.destAsPath(dest))
	}

	if isDestPublicInternet(dest) {
		for _, fip := range rt.config.fipList {
			if fipHasSource(src, fip) {
				// path through fip
				return vpcmodel.ConcatPaths(vpcmodel.PathFromResource(src), vpcmodel.PathFromResource(fip), vpcmodel.PathFromIPBlock(dest))
			}
		}
		for _, pgw := range rt.config.pgwList {
			if pgwHasSource(src, pgw) {
				// path through pgw
				return vpcmodel.ConcatPaths(vpcmodel.PathFromResource(src), vpcmodel.PathFromResource(pgw), vpcmodel.PathFromIPBlock(dest))
			}
		}
		// no path to public internet from src node
		return nil
	}

	for _, tgw := range rt.config.tgwList {
		logging.Debugf("look for dest %s in tgw.availableRoutes ", dest.ToIPAddressString())
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
				logging.Debugf("check available prefix: %s", prefix.ToCidrListString())
				if dest.ContainedIn(prefix) {
					// path through tgw
					// TODO: should be concatenated to path from tgw to dest by ingress routing table in the second vpc
					return vpcmodel.ConcatPaths(vpcmodel.PathFromResource(src), vpcmodel.PathFromTGWResource(tgw, vpcUID))
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

	logging.Debugf("could not find path on implicit routing table for dest %s", dest.ToIPAddressString())
	return nil
}
