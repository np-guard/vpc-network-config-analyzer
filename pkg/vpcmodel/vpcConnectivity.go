package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// detailed representation of allowed connectivity considering all resources in a vpc config instance
type VPCConnectivity struct {
	// computed for each node, by iterating its ConnectivityResult for all relevant VPC resources that capture it
	AllowedConns map[Node]*ConnectivityResult
	// combined connectivity - considering both ingress and egress per connection
	AllowedConnsCombined map[Node]map[Node]*common.ConnectionSet
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
}

func (v *VPCConnectivity) computeAllowedConnsCombined() {
	v.AllowedConnsCombined = map[Node]map[Node]*common.ConnectionSet{}

	for node, connectivityRes := range v.AllowedConns {
		for peerNode, conns := range connectivityRes.IngressAllowedConns {
			src := peerNode
			dst := node
			combinedConns := conns
			if peerNode.IsInternal() {
				egressConns := v.AllowedConns[peerNode].EgressAllowedConns[node]
				combinedConns.Intersection(*egressConns)
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
				combinedConns.Intersection(*ingressConss)
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[Node]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
	}
}

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
