package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// Functions for the computation of VPC connectivity between nodes elements

// GetVPCNetworkConnectivity computes VPCConnectivity in few steps
// (1) compute AllowedConns (map[Node]*ConnectivityResult) : ingress or egress allowed conns separately
// (2) compute AllowedConnsCombined (map[Node]map[Node]*common.ConnectionSet) : allowed conns considering both ingress and egress directions
// (3) compute AllowedConnsCombinedStateful : stateful allowed connections, for which connection in reverse direction is also allowed
func (c *CloudConfig) GetVPCNetworkConnectivity() *VPCConnectivity {
	res := &VPCConnectivity{
		AllowedConns:         map[Node]*ConnectivityResult{},
		AllowedConnsPerLayer: map[Node]map[string]*ConnectivityResult{},
	}
	// get connectivity in level of nodes elements
	for _, node := range c.Nodes {
		if !node.IsInternal() {
			continue
		}
		allIngressAllowedConns, ingressAllowedConnsPerLayer := c.getAllowedConnsPerDirection(true, node)
		allEgressAllowedConns, egressAllowedConnsPerLayer := c.getAllowedConnsPerDirection(false, node)

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
			res.AllowedConnsPerLayer[node][layer].EgressAllowedConns = egressAllowedConnsPerLayer[layer]
		}
	}
	res.computeAllowedConnsCombined()
	res.computeAllowedStatefulConnections()
	return res
}

func (c *CloudConfig) getAllowedConnsPerDirection(isIngress bool, capturedNode Node) (
	allLayersRes map[Node]*common.ConnectionSet, // result considering all layers
	perLayerRes map[string]map[Node]*common.ConnectionSet, // result separated per layer
) {
	perLayerRes = map[string]map[Node]*common.ConnectionSet{}
	allLayersRes = map[Node]*common.ConnectionSet{}
	var src, dst Node
	for _, peerNode := range c.Nodes {
		if peerNode.Cidr() == capturedNode.Cidr() {
			continue
		}
		if isIngress {
			src = peerNode
			dst = capturedNode
		} else {
			src = capturedNode
			dst = peerNode
		}
		if peerNode.IsInternal() {
			// no need for router node, connectivity is from within VPC
			// only check filtering resources
			allowedConnsBetweenCapturedAndPeerNode := AllConns()
			for _, filter := range c.FilterResources {
				layerName := filter.Kind()
				filteredConns := filter.AllowedConnectivity(src, dst, isIngress)
				if _, ok := perLayerRes[layerName]; !ok {
					perLayerRes[layerName] = map[Node]*common.ConnectionSet{}
				}
				perLayerRes[layerName][peerNode] = filteredConns
				allowedConnsBetweenCapturedAndPeerNode = allowedConnsBetweenCapturedAndPeerNode.Intersection(filteredConns)
				// do not break if empty, to enable computation for all layers
			}
			allLayersRes[peerNode] = allowedConnsBetweenCapturedAndPeerNode
			direction := "inbound"
			if !isIngress {
				direction = "outbound"
			}
			fmt.Printf("getAllowedConnsPerDirection: src: %s, dst %s, conn: %s, direction: %s\n", src.Cidr(), dst.Cidr(),
				allowedConnsBetweenCapturedAndPeerNode.String(), direction)
		} else { // else : external node -> consider attached routing resources
			allowedConnsBetweenCapturedAndPeerNode := NoConns()
			for _, router := range c.RoutingResources {
				routerConnRes := router.AllowedConnectivity(src, dst)
				if !routerConnRes.IsEmpty() { // connection is allowed through router resource
					// TODO: consider adding connection attribute with details of routing through this router resource
					allowedConnsBetweenCapturedAndPeerNode = routerConnRes
				}
			}
			for _, filter := range c.FilterResources {
				layerName := filter.Kind()
				filteredConns := filter.AllowedConnectivity(src, dst, isIngress)
				if _, ok := perLayerRes[layerName]; !ok {
					perLayerRes[layerName] = map[Node]*common.ConnectionSet{}
				}
				perLayerRes[layerName][peerNode] = filteredConns
				allowedConnsBetweenCapturedAndPeerNode = allowedConnsBetweenCapturedAndPeerNode.Intersection(filteredConns)
				// do not break if empty, to enable computation for all layers
			}
			allLayersRes[peerNode] = allowedConnsBetweenCapturedAndPeerNode
		}
	}
	return allLayersRes, perLayerRes
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
			combinedConns = combinedConns.Intersection(otherDirectionConns)
		}
		if _, ok := v.AllowedConnsCombined[src]; !ok {
			v.AllowedConnsCombined[src] = map[Node]*common.ConnectionSet{}
		}
		v.AllowedConnsCombined[src][dst] = combinedConns
	}
}

// computeAllowedConnsCombined computes combination of ingress&egress directions per connection allowed
// the result for this computation is stateless connections
// (could be that some of them or a subset of them are stateful,but this is not computed here)
func (v *VPCConnectivity) computeAllowedConnsCombined() {
	v.AllowedConnsCombined = map[Node]map[Node]*common.ConnectionSet{}
	for node, connectivityRes := range v.AllowedConns {
		v.computeCombinedConnectionsPerDirection(true, node, connectivityRes)
		v.computeCombinedConnectionsPerDirection(false, node, connectivityRes)
	}
}

func addDetailsLine(lines []string, details string) []string {
	if details != "" {
		lines = append(lines, details)
	}
	return lines
}

func getConnectionStr(src, dst, conn, suffix string) string {
	return fmt.Sprintf("%s => %s : %s%s\n", src, dst, conn, suffix)
}

func (v *VPCConnectivity) computeAllowedStatefulConnections() {
	// assuming v.AllowedConnsCombined was already computed

	// allowed connection: src->dst , requires NACL layer to allow dst->src (both ingress and egress)
	// on overlapping/matching connection-set, (src-dst ports should be switched),
	// for it to be considered as stateful

	v.AllowedConnsCombinedStateful = map[Node]map[Node]*common.ConnectionSet{}

	for src, connsMap := range v.AllowedConnsCombined {
		for dst, conn := range connsMap {
			// get the allowed *stateful* conn result
			// check allowed conns per NACL-layer from dst to src (dst->src)
			var DstAllowedEgressToSrc, SrcAllowedIngressFromDst *common.ConnectionSet
			// can dst egress to src?
			DstAllowedEgressToSrc = v.getPerLayerConnectivity(statelessLayerName, dst, src, false)
			// can src ingress from dst?
			SrcAllowedIngressFromDst = v.getPerLayerConnectivity(statelessLayerName, dst, src, true)
			combinedDstToSrc := DstAllowedEgressToSrc.Intersection(SrcAllowedIngressFromDst)

			if _, ok := v.AllowedConnsCombinedStateful[src]; !ok {
				v.AllowedConnsCombinedStateful[src] = map[Node]*common.ConnectionSet{}
			}
			// flip src/dst ports before intersection
			combinedDstToSrcSwitchPortsDirection := combinedDstToSrc.SwitchSrcDstPorts()
			v.AllowedConnsCombinedStateful[src][dst] = conn.Intersection(combinedDstToSrcSwitchPortsDirection)
		}
	}
}

// getPerLayerConnectivity currently used for "NaclLayer" - to compute stateful allowed conns
func (v *VPCConnectivity) getPerLayerConnectivity(layer string, src, dst Node, isIngress bool) *common.ConnectionSet {
	// if the analyzed input node is not internal- assume all conns allowed
	if (isIngress && !dst.IsInternal()) || (!isIngress && !src.IsInternal()) {
		return common.NewConnectionSet(true)
	}

	var connMap map[string]*ConnectivityResult
	if isIngress {
		connMap = v.AllowedConnsPerLayer[dst]
	} else {
		connMap = v.AllowedConnsPerLayer[src]
	}
	connResult := connMap[layer]
	if isIngress {
		return connResult.IngressAllowedConns[src]
	}
	return connResult.EgressAllowedConns[dst]
}

const (
	// this layer is stateless, thus required in both directions for stateful connectivity computation
	statelessLayerName = NaclLayer
)

func getCombinedConnsStr(combinedConns map[Node]map[Node]*common.ConnectionSet) string {
	strList := []string{}
	for src, nodeConns := range combinedConns {
		for dst, conns := range nodeConns {
			if conns.IsEmpty() {
				continue
			}
			srcName := src.Cidr()
			if src.IsInternal() {
				srcName = src.Name()
			}
			dstName := dst.Cidr()
			if dst.IsInternal() {
				dstName = dst.Name()
			}
			strList = append(strList, getConnectionStr(srcName, dstName, conns.String(), ""))
		}
	}
	sort.Strings(strList)
	return strings.Join(strList, "")
}

func (v *VPCConnectivity) String() string {
	res := "=================================== distributed inbound/outbound connections:\n"
	strList := []string{}
	for node, connectivity := range v.AllowedConns {
		// ingress
		for peerNode, conn := range connectivity.IngressAllowedConns {
			strList = append(strList, getConnectionStr(peerNode.Cidr(), node.Cidr(), conn.String(), " [inbound]"))
		}
		// egress
		for peerNode, conn := range connectivity.EgressAllowedConns {
			strList = append(strList, getConnectionStr(node.Cidr(), peerNode.Cidr(), conn.String(), " [outbound]"))
		}
	}
	sort.Strings(strList)
	res += strings.Join(strList, "")
	res += "=================================== combined connections:\n"
	strList = []string{}
	for src, nodeConns := range v.AllowedConnsCombined {
		for dst, conns := range nodeConns {
			strList = append(strList, getConnectionStr(src.Cidr(), dst.Cidr(), conns.String(), ""))
		}
	}
	sort.Strings(strList)
	res += strings.Join(strList, "")
	res += "=================================== combined connections - short version:\n"
	res += getCombinedConnsStr(v.AllowedConnsCombined)

	res += "=================================== stateful combined connections - short version:\n"
	res += getCombinedConnsStr(v.AllowedConnsCombinedStateful)
	return res
}
