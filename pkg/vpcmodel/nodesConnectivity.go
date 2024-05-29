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
// (3) compute AllowedConnsCombinedStateful : stateful allowed connections, for which connection in reverse direction is also allowed
// (4) if lbAbstraction required - abstract each lb separately
// (5) if grouping required - compute grouping of connectivity results
func (c *VPCConfig) GetVPCNetworkConnectivity(grouping, lbAbstraction bool) (res *VPCConnectivity, err error) {
	res = &VPCConnectivity{
		AllowedConns:         map[Node]*ConnectivityResult{},
		AllowedConnsPerLayer: map[Node]map[string]*ConnectivityResult{},
	}
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

		res.AllowedConns[node] = &ConnectivityResult{
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
	res.computeAllowedConnsCombined()
	res.computeAllowedStatefulConnections()
	res.abstractLoadBalancers(c.LoadBalancers, lbAbstraction)
	res.GroupedConnectivity, err = newGroupConnLines(c, res, grouping)
	return res, err
}

func (c *VPCConfig) deniedWithLBConnectivity(src, dst Node) bool {
	for _, lb := range c.LoadBalancers {
		if lb.DenyConnectivity(src, dst) {
			return true
		}
	}
	return false
}

func (c *VPCConfig) getFiltersAllowedConnsBetweenNodesPerDirectionAndLayer(
	src, dst Node,
	isIngress bool,
	layer string) (*connection.Set, error) {
	filter := c.getFilterTrafficResourceOfKind(layer)
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
		if c.deniedWithLBConnectivity(src, dst) {
			allLayersRes[peerNode] = NoConns()
			continue
		}

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
			// else : external node -> consider attached routing resources
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
			// ibm-config1: appliedFilters are either both nacl and sg (for pgw) or only sg (for fip)
			// TODO: consider moving to pkg ibm-vpc
			appliedFilters := appliedRouter.AppliedFiltersKinds()
			for layer := range appliedFilters {
				routerConnRes = routerConnRes.Intersect(perLayerRes[layer][peerNode])
			}
			allLayersRes[peerNode] = routerConnRes
		}
	}
	return allLayersRes, perLayerRes, nil
}

func switchSrcDstNodes(switchOrder bool, src, dst Node) (srcRes, dstRes Node) {
	if switchOrder {
		return dst, src
	}
	return src, dst
}

func (v *VPCConnectivity) computeCombinedConnectionsPerDirection(isIngressDirection bool, node Node, connectivityRes *ConnectivityResult) {
	for peerNode, conns := range connectivityRes.ingressOrEgressAllowedConns(isIngressDirection) {
		src, dst := switchSrcDstNodes(!isIngressDirection, peerNode, node)
		combinedConns := conns
		if peerNode.IsInternal() {
			if !isIngressDirection {
				continue
			}
			otherDirectionConns := v.AllowedConns[peerNode].ingressOrEgressAllowedConns(!isIngressDirection)[node]
			combinedConns = combinedConns.Intersect(otherDirectionConns)
		}
		v.AllowedConnsCombined.updateAllowedConnsMap(src, dst, combinedConns)
	}
}

// computeAllowedConnsCombined computes combination of ingress&egress directions per connection allowed
// the result for this computation is stateless connections
// (could be that some of them or a subset of them are stateful,but this is not computed here)
func (v *VPCConnectivity) computeAllowedConnsCombined() {
	v.AllowedConnsCombined = GeneralConnectivityMap{}
	for node, connectivityRes := range v.AllowedConns {
		v.computeCombinedConnectionsPerDirection(true, node, connectivityRes)
		v.computeCombinedConnectionsPerDirection(false, node, connectivityRes)
	}
}

func getConnectionStr(src, dst, conn, suffix string) string {
	return fmt.Sprintf("%s => %s : %s%s\n", src, dst, conn, suffix)
}

// given allowed conn from v.AllowedConnsCombined, check if it is external through FIP
func (v *VPCConnectivity) isConnExternalThroughFIP(src, dst Node) bool {
	var connRes *ConnectivityResult
	var isSrcPublic bool
	switch {
	case dst.IsPublicInternet():
		connRes = v.AllowedConnsPerLayer[src][fipRouter]
	case src.IsPublicInternet():
		connRes = v.AllowedConnsPerLayer[dst][fipRouter]
		isSrcPublic = true
	default:
		return false
	}
	if connRes == nil {
		return false
	}
	var conns *connection.Set
	if !isSrcPublic {
		conns = connRes.EgressAllowedConns[dst]
	} else {
		conns = connRes.IngressAllowedConns[src]
	}
	if conns != nil && !conns.IsEmpty() {
		return true
	}
	return false
}

// computeAllowedStatefulConnections adds the statefulness analysis for the computed allowed connections.
// In the connectivity output, a connection A -> B is stateful on TCP (allows bidrectional flow) if both SG and NACL
// (of A and B) allow connection (ingress and egress) from A to B , AND if NACL (of A and B) allow connection
// (ingress and egress) from B to A .
// if connection A->B (considering NACL & SG) is allowed with TCP, src_port: x_range, dst_port: y_range,
// and if connection B->A is allowed (considering NACL) with TCP, src_port: z_range, dst_port: w_range, then
// the stateful allowed connection A->B is TCP , src_port: x&w , dst_port: y&z.
func (v *VPCConnectivity) computeAllowedStatefulConnections() {
	// assuming v.AllowedConnsCombined was already computed

	// allowed connection: src->dst , requires NACL layer to allow dst->src (both ingress and egress)
	// on overlapping/matching connection-set, (src-dst ports should be switched),
	// for it to be considered as stateful

	v.AllowedConnsCombinedStateful = GeneralConnectivityMap{}

	for src, connsMap := range v.AllowedConnsCombined {
		for dst, conn := range connsMap {
			// src and dst here are nodes, always. Thus ignoring potential error in conversion
			srcNode := src.(Node)
			dstNode := dst.(Node)
			// iterate pairs (src,dst) with conn as allowed connectivity, to check stateful aspect
			if v.isConnExternalThroughFIP(srcNode, dstNode) {
				// TODO: this may be ibm-specific. consider moving to ibmvpc
				v.AllowedConnsCombinedStateful.updateAllowedConnsMap(src, dst, conn)
				conn.IsStateful = connection.StatefulTrue
				continue
			}

			// get the allowed *stateful* conn result
			// check allowed conns per NACL-layer from dst to src (dst->src)
			var DstAllowedEgressToSrc, SrcAllowedIngressFromDst *connection.Set
			// can dst egress to src?
			DstAllowedEgressToSrc = v.getPerLayerConnectivity(statelessLayerName, dstNode, srcNode, false)
			// can src ingress from dst?
			SrcAllowedIngressFromDst = v.getPerLayerConnectivity(statelessLayerName, dstNode, srcNode, true)
			combinedDstToSrc := DstAllowedEgressToSrc.Intersect(SrcAllowedIngressFromDst)
			// ConnectionWithStatefulness updates conn with IsStateful value, and returns the stateful subset
			statefulCombinedConn := conn.WithStatefulness(combinedDstToSrc)
			v.AllowedConnsCombinedStateful.updateAllowedConnsMap(src, dst, statefulCombinedConn)
		}
	}
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

func (v *VPCConnectivity) abstractLoadBalancers(loadBalancers []LoadBalancer, lbAbstraction bool) {
	if lbAbstraction {
		abstractionInfo := newNodeSetAbstraction(v.AllowedConnsCombined)
		for _, lb := range loadBalancers {
			ai := abstractionInfo.abstractNodeSet(lb)
			lb.SetAbstractionInfo(ai)
		}
		v.AllowedConnsCombined = abstractionInfo.abstractedConnectivity
	}
}

const (
	// this layer is stateless, thus required in both directions for stateful connectivity computation
	statelessLayerName = NaclLayer
	fipRouter          = "FloatingIP"
)

func (connectivityMap GeneralConnectivityMap) getCombinedConnsStr() string {
	strList := []string{}
	for src, nodeConns := range connectivityMap {
		for dst, conns := range nodeConns {
			// src and dst here are nodes, always. Thus ignoring potential error in conversion
			srcNode := src.(Node)
			dstNode := dst.(Node)
			if conns.IsEmpty() {
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
			connsStr := conns.EnhancedString()
			strList = append(strList, getConnectionStr(srcName, dstName, connsStr, ""))
		}
	}
	sort.Strings(strList)
	res := strings.Join(strList, "")
	return res
}

func (v *VPCConnectivity) String() string {
	return v.AllowedConnsCombined.getCombinedConnsStr()
}

func (v *VPCConnectivity) DetailedString() string {
	res := "=================================== distributed inbound/outbound connections:\n"
	strList := []string{}
	for node, connectivity := range v.AllowedConns {
		// ingress
		for peerNode, conn := range connectivity.IngressAllowedConns {
			strList = append(strList, getConnectionStr(peerNode.CidrOrAddress(), node.CidrOrAddress(), conn.String(), " [inbound]"))
		}
		// egress
		for peerNode, conn := range connectivity.EgressAllowedConns {
			strList = append(strList, getConnectionStr(node.CidrOrAddress(), peerNode.CidrOrAddress(), conn.String(), " [outbound]"))
		}
	}
	sort.Strings(strList)
	res += strings.Join(strList, "")
	res += "=================================== combined connections:\n"
	strList = []string{}
	for src, nodeConns := range v.AllowedConnsCombined {
		for dst, conns := range nodeConns {
			// src and dst here are nodes, always. Thus ignoring potential error in conversion
			strList = append(strList, getConnectionStr(src.(Node).CidrOrAddress(), dst.(Node).CidrOrAddress(), conns.String(), ""))
		}
	}
	sort.Strings(strList)
	res += strings.Join(strList, "")
	res += "=================================== combined connections - short version:\n"
	res += v.AllowedConnsCombined.getCombinedConnsStr()

	res += "=================================== stateful combined connections - short version:\n"
	res += v.AllowedConnsCombinedStateful.getCombinedConnsStr()
	return res
}
