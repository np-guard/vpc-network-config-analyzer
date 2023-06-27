package vpcmodel

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

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
	res.GroupedConnectivity = newGroupConnLines(c, res)
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
