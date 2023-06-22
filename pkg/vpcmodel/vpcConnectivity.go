package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// detailed representation of allowed connectivity considering all resources in a vpc config instance
type VPCConnectivity struct {
	// computed for each layer separately its allowed connections (ingress and egress separately)
	AllowedConnsPerLayer map[Node]map[string]*ConnectivityResult
	// computed for each node, by iterating its ConnectivityResult for all relevant VPC resources that capture it
	AllowedConns map[Node]*ConnectivityResult

	// combined connectivity - considering both ingress and egress per connection
	AllowedConnsCombined map[Node]map[Node]*common.ConnectionSet

	// allowed connectivity combined and stateful
	AllowedConnsCombinedStateful map[Node]map[Node]*common.ConnectionSet
}

type ConnectivityResult struct {
	IngressAllowedConns map[Node]*common.ConnectionSet
	EgressAllowedConns  map[Node]*common.ConnectionSet
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

/*func (v *VPCConnectivity) String() string {
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
	strList = []string{}
	for src, nodeConns := range v.AllowedConnsCombined {
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
	res += strings.Join(strList, "")
	return res
}*/

// computeAllowedConnsCombined computes combination of ingress&egress directions per connection allowed
// the result for this computation is stateless connections
// (could be that some of them or a subset of them are stateful,but this is not computed here)
func (v *VPCConnectivity) computeAllowedConnsCombined() {
	v.AllowedConnsCombined = map[Node]map[Node]*common.ConnectionSet{}

	for node, connectivityRes := range v.AllowedConns {
		for peerNode, conns := range connectivityRes.IngressAllowedConns {
			src := peerNode
			dst := node
			combinedConns := conns
			if peerNode.IsInternal() {
				egressConns := v.AllowedConns[peerNode].EgressAllowedConns[node]
				combinedConns = combinedConns.Intersection(egressConns)
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[Node]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
		for peerNode, conns := range connectivityRes.EgressAllowedConns {
			src := node
			dst := peerNode
			combinedConns := conns
			if peerNode.IsInternal() {
				ingressConss := v.AllowedConns[peerNode].IngressAllowedConns[node]
				combinedConns = combinedConns.Intersection(ingressConss)
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[Node]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
	}
}

/*
func (v *VPCConnectivity) computeAllowedConnsCombined() {
	v.AllowedConnsCombined = map[Node]map[Node]*common.ConnectionSet{}

	for node, connectivityRes := range v.AllowedConns {
		for peerNode, conns := range connectivityRes.IngressAllowedConns {
			src := peerNode
			dst := node
			combinedConns := conns
			if peerNode.IsInternal() {
				egressConns := v.AllowedConns[peerNode].EgressAllowedConns[node]
				combinedConns = combinedConns.Intersection(egressConns)
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[Node]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
		for peerNode, conns := range connectivityRes.EgressAllowedConns {
			src := node
			dst := peerNode
			combinedConns := conns
			if peerNode.IsInternal() {
				ingressConss := v.AllowedConns[peerNode].IngressAllowedConns[node]
				combinedConns = combinedConns.Intersection(ingressConss)
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[Node]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
	}
}
*/

func addDetailsLine(lines []string, details string) []string {
	if details != "" {
		lines = append(lines, details)
	}
	return lines
}

// add interface to output formatter

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
			DstAllowedEgressToSrc = v.getPerLayerConnectivity(statefulRequiredLayerName, dst, src, false)
			// can src ingress from dst?
			SrcAllowedIngressFromDst = v.getPerLayerConnectivity(statefulRequiredLayerName, dst, src, true)
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
	statefulRequiredLayerName = NaclLayer
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
