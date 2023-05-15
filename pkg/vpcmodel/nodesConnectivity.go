package vpcmodel

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

func (v *CloudConfig) GetVPCNetworkConnectivity() *VPCConnectivity {
	res := &VPCConnectivity{AllowedConns: map[Node]*ConnectivityResult{}}
	// get connectivity in level of nodes elements
	for _, node := range v.Nodes {
		if node.IsInternal() {
			res.AllowedConns[node] = &ConnectivityResult{
				IngressAllowedConns: v.getAllowedConnsPerDirection(true, node),
				EgressAllowedConns:  v.getAllowedConnsPerDirection(false, node),
			}
		}
	}
	res.computeAllowedConnsCombined()
	return res
}

func (v *CloudConfig) getAllowedConnsPerDirection(isIngress bool, capturedNode Node) map[Node]*common.ConnectionSet {
	res := map[Node]*common.ConnectionSet{}
	var src, dst Node
	for _, peerNode := range v.Nodes {
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
			for _, filter := range v.FilterResources {
				// TODO: cannot do intersection per all sg resources - connectivity is additive in sg layer .
				// only intersection between layers - sg vs nacl
				// each layer of filter resources should have its own logic
				// consider accumulate all filter resources of the same type, and send to a function that returns combined result.
				filteredConns := filter.AllowedConnectivity(src, dst, isIngress)
				allowedConnsBetweenCapturedAndPeerNode.Intersection(*filteredConns)
				if allowedConnsBetweenCapturedAndPeerNode.IsEmpty() {
					break
				}
			}
			res[peerNode] = allowedConnsBetweenCapturedAndPeerNode
			direction := "inbound"
			if !isIngress {
				direction = "outbound"
			}
			fmt.Printf("getAllowedConnsPerDirection: src: %s, dst %s, conn: %s, direction: %s\n", src.Cidr(), dst.Cidr(),
				allowedConnsBetweenCapturedAndPeerNode.String(), direction)
		} else { // else : external node -> consider attached routing resources
			allowedConnsBetweenCapturedAndPeerNode := NoConns()
			for _, router := range v.RoutingResources {
				routerConnRes := router.AllowedConnectivity(src, dst)
				if !routerConnRes.IsEmpty() { // connection is allowed through router resource
					// TODO: consider adding connection attribute with details of routing through this router resource
					allowedConnsBetweenCapturedAndPeerNode = routerConnRes
				}
			}
			for _, filter := range v.FilterResources {
				filteredConns := filter.AllowedConnectivity(src, dst, isIngress)
				allowedConnsBetweenCapturedAndPeerNode.Intersection(*filteredConns)
				if allowedConnsBetweenCapturedAndPeerNode.IsEmpty() {
					break
				}
			}
			res[peerNode] = allowedConnsBetweenCapturedAndPeerNode
		}
	}
	return res
}
