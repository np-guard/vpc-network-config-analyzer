package ibmvpc

import (
	"fmt"
	"strings"

	"github.com/np-guard/models/pkg/ipblock"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// routing_paths: this file contains types for representing routing paths and their endpoints
// a routing path is used to capture how traffic is routed within VPCs resources, given a src->dst pair

// path captures a list of endpoints within a routing path.
// The first endpoint is the src. The last endpoint is dest, or a nextHopEntry element.
type path []*endpoint

// endpoint captures possible types for elements within routing paths: concrete vpc resource, IP Address, and nextHopEntry
type endpoint struct {
	vpcResource vpcmodel.VPCResourceIntf
	ipBlock     *ipblock.IPBlock
	nextHop     *nextHopEntry
}

// nextHopEntry captures an endpoint within a routing path, which redirects traffic to its nextHop instead of the original dest
type nextHopEntry struct {
	nextHop  *ipblock.IPBlock // the next hop address
	origDest *ipblock.IPBlock // the original destination
	rt       *routingTable    // the routing table from which this next hop was determined
}

const pathConnector string = " -> "

func (p path) string() string {
	return strings.Join(p.listEndpointsStrings(), pathConnector)
}

func (p path) empty() bool {
	return len(p) == 0
}

func (p path) listEndpointsStrings() []string {
	res := make([]string, len(p))
	for i := range p {
		res[i] = p[i].string()
	}
	return res
}

func (p path) equal(otherPath path) bool {
	if len(p) != len(otherPath) {
		return false
	}
	for i := range p {
		if !p[i].equal(otherPath[i]) {
			return false
		}
	}
	return true
}

func (e *endpoint) string() string {
	switch {
	case e.vpcResource != nil:
		return fmt.Sprintf("%s - %s", e.vpcResource.Kind(), e.vpcResource.Name())
	case e.ipBlock != nil:
		return ipBlockString(e.ipBlock)
	case e.nextHop != nil:
		return e.nextHop.string()
	}
	return ""
}

func (e *endpoint) equal(otherEndpoint *endpoint) bool {
	switch {
	case e.nextHop != nil:
		if !otherEndpoint.nextHop.equal(e.nextHop) {
			return false
		}
	case e.vpcResource != nil:
		if otherEndpoint.vpcResource == nil || otherEndpoint.vpcResource.UID() != e.vpcResource.UID() {
			return false
		}
	case
		e.ipBlock != nil:
		if otherEndpoint.ipBlock == nil || !e.ipBlock.Equal(otherEndpoint.ipBlock) {
			return false
		}
	default:
		return false // should not get here
	}
	return true
}

func (n *nextHopEntry) string() string {
	return fmt.Sprintf("nextHop: %s [origDest: %s]", ipBlockString(n.nextHop), ipBlockString(n.origDest))
}

func (n *nextHopEntry) equal(other *nextHopEntry) bool {
	return n.nextHop.Equal(other.nextHop) &&
		n.origDest.Equal(other.origDest)
	// TODO: add comparison of rt ?
}

func ipBlockString(ipb *ipblock.IPBlock) string {
	if ipAddress := ipb.ToIPAddressString(); ipAddress != "" {
		return ipAddress
	}
	return ipb.ToCidrListString()
}
