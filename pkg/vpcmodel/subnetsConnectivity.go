/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"errors"
	"fmt"

	"github.com/np-guard/models/pkg/connection"
	"github.com/np-guard/models/pkg/ipblock"
)

// VPCsubnetConnectivity captures allowed connectivity for subnets, considering nacl and pgw resources
type VPCsubnetConnectivity struct {
	VPCConfig *VPCConfig

	// computed for each node (subnet), by iterating its ConnectivityResult for all relevant VPC resources that capture it
	// computed for each subnet, by iterating its ConfigBasedConnectivityResults for all relevant VPC resources that capture it
	// a subnet is mapped to its set of  its allowed ingress (egress) communication as captured by
	// pairs of external ip/subnet+connection
	// This is auxiliary computation based on which AllowedConnsCombinedResponsive is computed
	// todo: add debug output mode based on this structure
	AllowedConns map[VPCResourceIntf]*ConfigBasedConnectivityResults

	// combined connectivity - considering both ingress and egress per connection
	// The main outcome of the computation of which the outputs is based
	// For each src node provides a map of dsts and the connection it has to these dsts,
	// including information regarding the tcp-responsive, tcp-non responsive and non-tcp connection
	AllowedConnsCombinedResponsive GeneralResponsiveConnectivityMap

	// grouped connectivity result
	GroupedConnectivity *GroupConnLines
}

const (
	subnetKind                = "Subnet"
	pgwKind                   = "PublicGateway"
	igwKind                   = "InternetGateway"
	errUnexpectedTypePeerNode = "unexpected type for peerNode in computeAllowedConnsCombined"
)

func subnetConnLine(subnet string, conn *connection.Set) string {
	return fmt.Sprintf("%s : %s\n", subnet, conn.String())
}

func (c *ConfigBasedConnectivityResults) string(config *VPCConfig) string {
	res := "Ingress: \n"
	for n, conn := range c.IngressAllowedConns {
		res += subnetConnLine(n.NameForAnalyzerOut(config), conn)
	}
	res += "Egress: \n"
	for n, conn := range c.EgressAllowedConns {
		res += subnetConnLine(n.NameForAnalyzerOut(config), conn)
	}

	return res
}

var _ = (*VPCsubnetConnectivity).printAllowedConns // avoiding "unused" warning

// print AllowedConns (not combined)
func (v *VPCsubnetConnectivity) printAllowedConns(c *VPCConfig) {
	for n, connMap := range v.AllowedConns {
		fmt.Println(n.NameForAnalyzerOut(c))
		fmt.Println(connMap.string(v.VPCConfig))
		fmt.Println("-----------------")
	}
}

func (c *VPCConfig) ipblockToNamedResourcesInConfig(ipb *ipblock.IPBlock, excludeExternalNodes bool) ([]VPCResourceIntf, error) {
	res := []VPCResourceIntf{}

	// consider subnets
	for _, subnet := range c.Subnets {
		var subnetCidrIPB *ipblock.IPBlock
		if subnetCidrIPB = subnet.AddressRange(); subnetCidrIPB == nil {
			return nil, errors.New("missing AddressRange for subnet")
		}
		if subnetCidrIPB.ContainedIn(ipb) {
			res = append(res, subnet)
		} else if subnetCidrIPB.Overlap(ipb) {
			// the ACL splits connectivity to part of that subnet,
			// this is currently not supported in subnets connectivity analysis
			return nil, fmt.Errorf("unsupported subnets connectivity analysis - no consistent connectivity for entire subnet %s",
				subnet.NameForAnalyzerOut(c))
		}
	}

	if excludeExternalNodes {
		return res, nil
	}

	// consider external nodes
	for _, exn := range c.Nodes {
		if exn.IsInternal() {
			continue
		}
		nodeCidrIPB := exn.IPBlock()
		if nodeCidrIPB.ContainedIn(ipb) {
			res = append(res, exn)
		}
	}

	return res, nil
}

func (c *VPCConfig) convertIPbasedToSubnetBasedResult(ipconn *IPbasedConnectivityResult, excludeExternalNodes bool) (
	*ConfigBasedConnectivityResults,
	error,
) {
	res := NewConfigBasedConnectivityResults()

	for ipb, conn := range ipconn.IngressAllowedConns {
		// PGW does not allow ingress traffic but the ingress is required for the responsive computation
		if namedResources, err := c.ipblockToNamedResourcesInConfig(ipb, excludeExternalNodes); err == nil {
			for _, n := range namedResources {
				res.IngressAllowedConns[n] = conn
			}
		} else {
			return nil, err
		}
	}

	// egress traffic to external nodes may be enabled by a public gateway
	for ipb, conn := range ipconn.EgressAllowedConns {
		if namedResources, err := c.ipblockToNamedResourcesInConfig(ipb, excludeExternalNodes); err == nil {
			for _, n := range namedResources {
				res.EgressAllowedConns[n] = conn
			}
		} else {
			return nil, err
		}
	}
	return res, nil
}

func getSubnetsForPGW(c *VPCConfig, pgw RoutingResource, externalNode Node) (res []NodeSet) {
	for _, subnet := range c.Subnets {
		conn, err := pgw.AllowedConnectivity(subnet, externalNode)
		if err == nil && conn.IsAll() {
			res = append(res, subnet)
		}
	}
	return res
}

func getSomeExternalNode(c *VPCConfig) Node {
	for _, n := range c.Nodes {
		if n.IsExternal() {
			return n
		}
	}
	return nil
}

func getSubnetsWithPGW(c *VPCConfig) map[string]bool {
	someExternalNode := getSomeExternalNode(c)
	res := map[string]bool{}
	for _, r := range c.RoutingResources {
		if r.Kind() == pgwKind || r.Kind() == igwKind {
			attachedSubnets := getSubnetsForPGW(c, r, someExternalNode)
			for _, subnet := range attachedSubnets {
				res[subnet.AddressRange().ToCidrListString()] = true
			}
		}
	}
	return res
}

// the main function to compute connectivity per subnet based on resources that capture subnets, such as nacl, pgw, tgw, routing-tables
func (c *VPCConfig) GetSubnetsConnectivity(includePGW bool, groupingType int) (*VPCsubnetConnectivity, error) {
	var subnetsConnectivityFromACLresources map[string]*IPbasedConnectivityResult
	var err error
	for _, fl := range c.FilterResources {
		if fl.Kind() == NaclLayer {
			subnetsConnectivityFromACLresources, err = fl.ConnectivityMap()
			if err != nil {
				return nil, err
			}
		}
	}
	if subnetsConnectivityFromACLresources == nil {
		return nil, errors.New("missing connectivity results from NACL resources")
	}

	subnetsWithPGW := getSubnetsWithPGW(c)

	// convert to subnet-based connectivity result
	subnetsConnectivity := map[VPCResourceIntf]*ConfigBasedConnectivityResults{}
	for subnetCidrStr, ipBasedConnectivity := range subnetsConnectivityFromACLresources {
		subnet, err1 := c.SubnetCidrToSubnetElem(subnetCidrStr)
		if err1 != nil {
			return nil, err1
		}

		// create and update configBasedConns according to relevant router (pgw) resources
		subnetHasPGW := false
		if subnetsWithPGW[subnetCidrStr] {
			subnetHasPGW = true
		}
		if !includePGW {
			subnetHasPGW = true // do not limit connectivity to external nodes only if has actual PGW
		}
		excludeExternalNodes := !subnetHasPGW || subnet.IsPrivate()
		configBasedConns, err2 := c.convertIPbasedToSubnetBasedResult(ipBasedConnectivity, excludeExternalNodes)
		if err2 != nil {
			return nil, err2
		}

		subnetsConnectivity[subnet] = configBasedConns
	}

	res := &VPCsubnetConnectivity{AllowedConns: subnetsConnectivity, VPCConfig: c}

	// get combined connections from subnetsConnectivity
	allowedConnsCombined, err3 := res.computeAllowedConnsCombined()
	if err3 != nil {
		return nil, err3
	}
	if err4 := res.computeResponsiveConnections(allowedConnsCombined); err4 != nil {
		return nil, err4
	}

	groupedConnectivity, err5 := newGroupConnLinesSubnetConnectivity(c, res, groupingType)
	if err5 != nil {
		return nil, err5
	}
	res.GroupedConnectivity = groupedConnectivity

	return res, nil
}

// updateSubnetsConnectivityByTransitGateway checks if subnets pair (src,dst) cross-vpc connection is enabled by tgw,
// and if yes - returns the original computed combinedConns, else returns no-conns object
func updateSubnetsConnectivityByTransitGateway(src, dst VPCResourceIntf,
	combinedConns *connection.Set,
	c *VPCConfig) (
	*connection.Set, error) {
	// assuming a single router representing the tgw for a "MultipleVPCsConfig"
	if len(c.RoutingResources) != 2 { // expecting tgw and sgw (virtual gateway)
		return nil, fmt.Errorf("unexpected number of RoutingResources for MultipleVPCsConfig, expecting only TGW")
	}
	tgw := c.RoutingResources[0]
	connections, err := tgw.AllowedConnectivity(src, dst)
	if err != nil {
		return nil, err
	}
	if connections.IsAll() {
		return combinedConns, nil
	}
	return NoConns(), nil
}

func (v *VPCsubnetConnectivity) computeAllowedConnsCombined() (GeneralConnectivityMap, error) {
	allowedConnsCombined := GeneralConnectivityMap{}
	for subnetNodeSet, connsRes := range v.AllowedConns {
		for peerNode, conns := range connsRes.IngressAllowedConns {
			src := peerNode
			dst := subnetNodeSet
			considerPair, err := v.VPCConfig.shouldConsiderPairForConnectivity(src, dst)
			if err != nil {
				return nil, err
			}
			if !considerPair {
				continue
			}
			var combinedConns *connection.Set
			// peerNode kind is expected to be Subnet or External
			peerNodeObj := v.VPCConfig.UIDToResource[peerNode.UID()]
			switch concPeerNode := peerNodeObj.(type) {
			case NodeSet:
				egressConns := v.AllowedConns[concPeerNode].EgressAllowedConns[subnetNodeSet]
				if egressConns == nil {
					// should not get here
					return nil, fmt.Errorf("could not find egress connection from %s to  %s",
						concPeerNode.NameForAnalyzerOut(v.VPCConfig), subnetNodeSet.NameForAnalyzerOut(v.VPCConfig))
				}
				combinedConns = conns.Intersect(egressConns)
				// for subnets cross-vpc connection, add intersection with tgw connectivity (prefix filters)
				if v.VPCConfig.IsMultipleVPCsConfig {
					combinedConns, err = updateSubnetsConnectivityByTransitGateway(src, dst, combinedConns, v.VPCConfig)
					if err != nil {
						return nil, err
					}
				}
			case *ExternalNetwork:
				// PGW does not allow ingress traffic
			default:
				return nil, errors.New(errUnexpectedTypePeerNode)
			}
			if combinedConns == nil {
				continue
			}
			allowedConnsCombined.updateAllowedConnsMap(src, dst, combinedConns)
		}
		for peerNode, conns := range connsRes.EgressAllowedConns {
			src := subnetNodeSet
			dst := peerNode
			if src.Name() == dst.Name() {
				continue
			}
			combinedConns := conns

			// peerNode kind is expected to be Subnet or External
			peerNodeObj := v.VPCConfig.UIDToResource[peerNode.UID()]
			switch peerNodeObj.(type) {
			case NodeSet:
				continue
			case *ExternalNetwork:
				// do nothing
			default:
				return nil, errors.New(errUnexpectedTypePeerNode)
			}
			allowedConnsCombined.updateAllowedConnsMap(src, dst, combinedConns)
		}
	}
	return allowedConnsCombined, nil
}

func (v *VPCsubnetConnectivity) computeResponsiveConnections(allowedConnsCombined GeneralConnectivityMap) error {
	v.AllowedConnsCombinedResponsive = GeneralResponsiveConnectivityMap{}
	for src, endpointConns := range allowedConnsCombined {
		for dst, conn := range endpointConns {
			if conn.IsEmpty() {
				continue
			}
			dstObj := v.VPCConfig.UIDToResource[dst.UID()]
			var otherDirectionConn *connection.Set
			switch dstObj.(type) {
			case NodeSet:
				otherDirectionConn = allowedConnsCombined[dst][src]
			case *ExternalNetwork:
				// subnet to external node is responsive if the subnet's nacl allows ingress from that node.
				// This connection will *not* be considered by AllowedConnsCombined since ingress connection
				// from external nodes can not be initiated for pgw
				otherDirectionConn = v.AllowedConns[src].IngressAllowedConns[dst]
			default:
				return fmt.Errorf("computeResponsiveConnections: unexpected type for input dst")
			}
			detailedConnSet := computeDetailedConn(conn, otherDirectionConn)
			v.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(src, dst, detailedConnSet)
		}
	}
	return nil
}

// GetConnectivityOutputPerEachSubnetSeparately returns string results of connectivity analysis per
// single subnet with its attached nacl, separately per subnet - useful to get understanding of the
// connectivity implied from nacl configuration applied on a certain subnet in the vpc
func (c *VPCConfig) GetConnectivityOutputPerEachSubnetSeparately() string {
	// iterate over all subnets, collect all outputs per subnet connectivity
	for _, r := range c.FilterResources {
		if r.Kind() == NaclLayer {
			return r.GetConnectivityOutputPerEachElemSeparately()
		}
	}
	return ""
}
