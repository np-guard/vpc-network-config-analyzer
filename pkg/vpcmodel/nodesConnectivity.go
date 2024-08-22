/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/connection"
)

// Functions for the computation of VPC connectivity between nodes elements

// GetVPCNetworkConnectivity computes VPCConnectivity in few steps
// (1) compute AllowedConns (map[Node]*ConnectivityResult) : ingress or egress allowed conns separately
// (2) compute AllowedConnsCombined (map[Node]map[Node]*connection.Set) : allowed conns considering both ingress and egress directions
// (3) compute AllowedConnsCombinedResponsive extension of AllowedConnsCombined to contain accurate responsive info
// (4) if lbAbstraction required - abstract each lb separately
// (5) if grouping required - compute grouping of connectivity results
func (c *VPCConfig) GetVPCNetworkConnectivity(grouping, lbAbstraction bool) (res *VPCConnectivity, err error) {
	res = &VPCConnectivity{
		AllowedConnsPerLayer: map[Node]map[string]*ConnectivityResult{},
	}
	// allowedConns - set of node's allowed ingress (egress) communication as captured by pairs of node+connection
	allowedConns := map[Node]*ConnectivityResult{}
	// get connectivity in level of nodes elements
	for _, node := range c.Nodes {
		if !node.IsInternal() {
			continue
		}
		allIngressAllowedConns, ingressAllowedConnsPerLayer, err1 := c.getAllowedConnsPerDirection(true, node)
		if err1 != nil {
			return nil, err1
		}
		allEgressAllowedConns, egressAllowedConnsPerLayer, err2 := c.getAllowedConnsPerDirection(false, node)
		if err2 != nil {
			return nil, err2
		}

		allowedConns[node] = &ConnectivityResult{
			IngressAllowedConns: allIngressAllowedConns,
			EgressAllowedConns:  allEgressAllowedConns,
		}
		res.AllowedConnsPerLayer[node] = map[string]*ConnectivityResult{}
		for layer := range ingressAllowedConnsPerLayer {
			res.AllowedConnsPerLayer[node][layer] = &ConnectivityResult{
				IngressAllowedConns: ingressAllowedConnsPerLayer[layer],
			}
		}
		for layer := range egressAllowedConnsPerLayer {
			if res.AllowedConnsPerLayer[node][layer] == nil {
				res.AllowedConnsPerLayer[node][layer] = &ConnectivityResult{}
			}
			res.AllowedConnsPerLayer[node][layer].EgressAllowedConns = egressAllowedConnsPerLayer[layer]
		}
	}
	allowedConnsCombined := res.computeAllowedConnsCombined(allowedConns)
	err3 := res.computeAllowedResponsiveConnections(c, allowedConnsCombined)
	if err3 != nil {
		return nil, err3
	}
	res.abstractLoadBalancers(c.LoadBalancers, lbAbstraction)
	res.GroupedConnectivity, err = newGroupConnLines(c, res, grouping)
	return res, err
}

func (c *VPCConfig) getLoadBalancerRule(src, dst Node) LoadBalancerRule {
	for _, lb := range c.LoadBalancers {
		if rule := lb.GetLoadBalancerRule(src, dst); rule != nil {
			return rule
		}
	}
	return nil
}

func (c *VPCConfig) getPrivateSubnetRule(src, dst Node) PrivateSubnetRule {
	switch {
	case dst.IsInternal():
		return dst.(InternalNodeIntf).Subnet().GetPrivateSubnetRule(src, dst)
	case src.IsInternal():
		return src.(InternalNodeIntf).Subnet().GetPrivateSubnetRule(src, dst)
	}
	return nil
}

// getNonFilterNonRouterRulesConn() return the connectivity of all rules that are not part of the filters and routers.
func (c *VPCConfig) getNonFilterNonRouterRulesConn(src, dst Node, isIngress bool) *connection.Set {
	loadBalancerRule := c.getLoadBalancerRule(src, dst)
	if loadBalancerRule != nil && loadBalancerRule.Deny(isIngress) {
		return NoConns()
	}
	privateSubnetRule := c.getPrivateSubnetRule(src, dst)
	if privateSubnetRule != nil && privateSubnetRule.Deny(isIngress) {
		return NoConns()
	}
	return AllConns()
}

func (c *VPCConfig) getFiltersAllowedConnsBetweenNodesPerDirectionAndLayer(
	src, dst Node,
	isIngress bool,
	layer string) (*connection.Set, error) {
	filter := c.GetFilterTrafficResourceOfKind(layer)
	if filter == nil {
		return AllConns(), nil
	}
	return filter.AllowedConnectivity(src, dst, isIngress)
}

func updatePerLayerRes(res map[string]map[Node]*connection.Set, layer string, node Node, conn *connection.Set) {
	if _, ok := res[layer]; !ok {
		res[layer] = map[Node]*connection.Set{}
	}
	res[layer][node] = conn
}

// getAllowedConnsPerDirection returns: (1) map of allowed (ingress or egress) connectivity for capturedNode, considering
// all relevant resources (nacl/sg/fip/pgw) , and (2) similar map per separated layers only (nacl/sg)
func (c *VPCConfig) getAllowedConnsPerDirection(isIngress bool, capturedNode Node) (
	allLayersRes map[Node]*connection.Set, // result considering all layers
	perLayerRes map[string]map[Node]*connection.Set, // result separated per layer
	err error,
) {
	perLayerRes = map[string]map[Node]*connection.Set{}
	allLayersRes = map[Node]*connection.Set{}

	// iterate pairs (capturedNode, peerNode) to analyze their allowed ingress/egress conns
	for _, peerNode := range c.Nodes {
		// skip analysis between certain pairs of nodes
		considerPair, err := c.shouldConsiderPairForConnectivity(capturedNode, peerNode)
		if err != nil {
			return nil, nil, err
		}
		if !considerPair {
			continue
		}
		src, dst := switchSrcDstNodes(!isIngress, peerNode, capturedNode)

		// first compute connectivity per layer of filters resources
		filterLayers := []string{NaclLayer, SecurityGroupLayer}
		for _, layer := range filterLayers {
			conns, err1 := c.getFiltersAllowedConnsBetweenNodesPerDirectionAndLayer(src, dst, isIngress, layer)
			if err1 != nil {
				return nil, nil, err1
			}
			updatePerLayerRes(perLayerRes, layer, peerNode, conns)
		}

		if peerNode.IsInternal() {
			var allowedConnsBetweenCapturedAndPeerNode *connection.Set
			if c.IsMultipleVPCsConfig {
				// in case of cross-vpc connectivity, do need a router (tgw) enabling this connection
				_, allowedConnsBetweenCapturedAndPeerNode, err = c.getRoutingResource(src, dst)
				if err != nil {
					return nil, nil, err
				}
			} else {
				// no need for router, connectivity is from within VPC
				allowedConnsBetweenCapturedAndPeerNode = AllConns()
			}
			// now check filtering resources
			for _, resMap := range perLayerRes {
				allowedConnsBetweenCapturedAndPeerNode = allowedConnsBetweenCapturedAndPeerNode.Intersect(resMap[peerNode])
			}
			allLayersRes[peerNode] = allowedConnsBetweenCapturedAndPeerNode
		} else {
			// else : external node -> needs external router, which considers both NACL and SG
			appliedRouter, routerConnRes, err := c.getRoutingResource(src, dst)
			if err != nil {
				return nil, nil, err
			}
			if appliedRouter != nil {
				updatePerLayerRes(perLayerRes, appliedRouter.Kind(), peerNode, routerConnRes)
			} else {
				// without fip/pgw there is no external connectivity
				allLayersRes[peerNode] = NoConns()
				continue
			}
			// TODO: consider moving to pkg ibm-vpc
			for _, layer := range filterLayers {
				routerConnRes = routerConnRes.Intersect(perLayerRes[layer][peerNode])
			}
			allLayersRes[peerNode] = routerConnRes
		}
		moreRulesConn := c.getNonFilterNonRouterRulesConn(src, dst, isIngress)
		allLayersRes[peerNode] = allLayersRes[peerNode].Intersect(moreRulesConn)
	}
	return allLayersRes, perLayerRes, nil
}

func switchSrcDstNodes(switchOrder bool, src, dst Node) (srcRes, dstRes Node) {
	if switchOrder {
		return dst, src
	}
	return src, dst
}

func (allowConnCombined *GeneralConnectivityMap) computeCombinedConnectionsPerDirection(isIngressDirection bool, node Node,
	connectivityRes *ConnectivityResult, allowedConns map[Node]*ConnectivityResult) {
	for peerNode, conns := range connectivityRes.ingressOrEgressAllowedConns(isIngressDirection) {
		src, dst := switchSrcDstNodes(!isIngressDirection, peerNode, node)
		combinedConns := conns
		if peerNode.IsInternal() {
			if !isIngressDirection {
				continue
			}
			otherDirectionConns := allowedConns[peerNode].ingressOrEgressAllowedConns(!isIngressDirection)[node]
			combinedConns = combinedConns.Intersect(otherDirectionConns)
		}
		allowConnCombined.updateAllowedConnsMap(src, dst, combinedConns)
	}
}

// computeAllowedConnsCombined computes combination of ingress&egress directions per connection allowed
// the responsive state of the connectivity is not computed here
func (v *VPCConnectivity) computeAllowedConnsCombined(allowedConns map[Node]*ConnectivityResult) GeneralConnectivityMap {
	allowedConnsCombined := GeneralConnectivityMap{}
	for node, connectivityRes := range allowedConns {
		allowedConnsCombined.computeCombinedConnectionsPerDirection(true, node, connectivityRes, allowedConns)
		allowedConnsCombined.computeCombinedConnectionsPerDirection(false, node, connectivityRes, allowedConns)
	}
	return allowedConnsCombined
}

func getConnectionStr(src, dst, conn, suffix string) string {
	return fmt.Sprintf("%s => %s : %s%s\n", src, dst, conn, suffix)
}

// computeAllowedResponsiveConnections adds the responsiveness analysis for the computed allowed connections.
// A connection A -> B is considered responsive if:
// Each connection A -> B is being split into 3 parts (each of which could be empty)
// 1. Responsive: A  TCP (allows bidrectional flow) connection s.t.: both SG and NACL
// (of A and B) allow connection (ingress and egress) from A to B , AND if NACL (of A and B) allow connection
// (ingress and egress) from B to A .
// Specifically, if connection A->B (considering NACL & SG) is allowed with TCP, src_port: x_range, dst_port: y_range,
// and if connection B->A is allowed (considering NACL) with TCP, src_port: z_range, dst_port: w_range, then
// the responsive allowed connection A->B is TCP , src_port: x&w , dst_port: y&z.
// 2. Not responsive: the tcp part of the connection that is not in 1
// 3. Other: the non-tcp part of the connection (for which the responsive question is non-relevant)
func (v *VPCConnectivity) computeAllowedResponsiveConnections(c *VPCConfig,
	allowedConnsCombined GeneralConnectivityMap) error {
	// assuming v.AllowedConnsCombined was already computed

	// allowed connection: src->dst , requires NACL layer to allow dst->src (both ingress and egress)
	// on overlapping/matching connection-set, (src-dst ports should be switched),
	// for it to be considered responsive

	v.AllowedConnsCombinedResponsive = GeneralResponsiveConnectivityMap{}

	for src, connsMap := range allowedConnsCombined {
		for dst, conn := range connsMap {
			// src and dst here are nodes, always. Thus ignoring potential error in conversion
			srcNode := src.(Node)
			dstNode := dst.(Node)
			// get the allowed *responsive* conn result
			// check allowed conns per NACL-layer from dst to src (dst->src) (since SG is stateful)
			var DstAllowedEgressToSrc, SrcAllowedIngressFromDst *connection.Set
			// can dst egress to src?
			DstAllowedEgressToSrc = v.getPerLayerConnectivity(statelessLayerName, dstNode, srcNode, false)
			// can src ingress from dst?
			SrcAllowedIngressFromDst = v.getPerLayerConnectivity(statelessLayerName, dstNode, srcNode, true)
			combinedDstToSrc := DstAllowedEgressToSrc.Intersect(SrcAllowedIngressFromDst)
			// in case the connection is multi-vpc: does the tgw enable respond?
			if c.IsMultipleVPCsConfig {
				_, allowedConnsBetweenCapturedAndPeerNode, err := c.getRoutingResource(dstNode, srcNode)
				if err != nil {
					return err
				}
				combinedDstToSrc = combinedDstToSrc.Intersect(allowedConnsBetweenCapturedAndPeerNode)
			}
			detailedConnSet := computeDetailedConn(conn, combinedDstToSrc)
			v.AllowedConnsCombinedResponsive.updateAllowedResponsiveConnsMap(src, dst, detailedConnSet)
		}
	}
	return nil
}

// getPerLayerConnectivity currently used for "NaclLayer" - to compute stateful allowed conns
func (v *VPCConnectivity) getPerLayerConnectivity(layer string, src, dst Node, isIngress bool) *connection.Set {
	// if the analyzed input node is not internal- assume all conns allowed
	if (isIngress && !dst.IsInternal()) || (!isIngress && !src.IsInternal()) {
		return connection.All()
	}
	var result *connection.Set
	var connMap map[string]*ConnectivityResult
	if isIngress {
		connMap = v.AllowedConnsPerLayer[dst]
	} else {
		connMap = v.AllowedConnsPerLayer[src]
	}
	connResult := connMap[layer]
	if isIngress {
		result = connResult.IngressAllowedConns[src]
	} else {
		result = connResult.EgressAllowedConns[dst]
	}
	if result == nil {
		return NoConns()
	}
	return result
}

// load balancer abstraction:
// currently, AllowedConnsCombined contains the private IPs of the load balancer.
// the abstraction creates new AllowedConnsCombined,
// it replaces the private IPs in the with the load balancer itself
// for each load balancer, it keeps the abstractionInfo, to be used later
// see details at nodeSetConnectivityAbstraction()
func (v *VPCConnectivity) abstractLoadBalancers(loadBalancers []LoadBalancer, lbAbstraction bool) {
	if lbAbstraction {
		nodeAbstraction := newNodeSetAbstraction(v.AllowedConnsCombinedResponsive)
		for _, lb := range loadBalancers {
			abstractionInfo := nodeAbstraction.abstractNodeSet(lb)
			lb.SetAbstractionInfo(abstractionInfo)
		}
		v.AllowedConnsCombinedResponsive = nodeAbstraction.abstractedConnectivity
	}
}

const (
	// this layer is stateless, thus required in both directions for stateful connectivity computation
	statelessLayerName = NaclLayer
	fipRouter          = "FloatingIP"
)

func (responsiveConnMap GeneralResponsiveConnectivityMap) getCombinedConnsStr(onlyBidirectional bool) string {
	strList := []string{}
	for src, nodeExtendedConns := range responsiveConnMap {
		for dst, extConns := range nodeExtendedConns {
			// src and dst here are nodes, always. Thus ignoring potential error in conversion
			srcNode := src.(Node)
			dstNode := dst.(Node)
			if extConns.isEmpty() {
				continue
			}
			srcName := srcNode.CidrOrAddress()
			if srcNode.IsInternal() {
				srcName = src.Name()
			}
			dstName := dstNode.CidrOrAddress()
			if dstNode.IsInternal() {
				dstName = dst.Name()
			}
			var connsStr string
			if onlyBidirectional {
				bidirectional := extConns.tcpRspEnable.Union(extConns.nonTCP)
				connsStr = bidirectional.String()
			} else {
				connsStr = extConns.string()
			}
			strList = append(strList, getConnectionStr(srcName, dstName, connsStr, ""))
		}
	}
	sort.Strings(strList)
	res := strings.Join(strList, "")
	return res
}

func (v *VPCConnectivity) String() string {
	return v.AllowedConnsCombinedResponsive.getCombinedConnsStr(false)
}
