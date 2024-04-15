package vpcmodel

import "fmt"

type srcDstEndPoint struct {
	c   *VPCConfig
	src EndpointElem
	dst EndpointElem
}

// MultiExplain multi-explanation mode: given a slice of <VPCConfig, Endpoint, Endpoint> such that each Endpoint is either
// a vsi or grouped external addresses of the given config, returns a corresponding slice of [] *Explanation
func MultiExplain(srcDstCouples []srcDstEndPoint) (multiExplanation []*Explanation, err error) {
	multiExplanation = make([]*Explanation, len(srcDstCouples))
	vpcsConnects := map[string]*VPCConnectivity{}
	for i, v := range srcDstCouples {
		srcNodes, errSrc := getNodesFromEndpoint(v.src)
		if errSrc != nil {
			return nil, errSrc
		}
		dstNodes, errDst := getNodesFromEndpoint(v.src)
		if errDst != nil {
			return nil, errSrc
		}
		var connectivity *VPCConnectivity
		var ok bool
		if connectivity, ok = vpcsConnects[v.c.VPC.Name()]; !ok {
			connectivity, err = v.c.GetVPCNetworkConnectivity(false) // computes connectivity
			if err != nil {
				return nil, err
			}
			vpcsConnects[v.c.VPC.Name()] = connectivity
		}
		explain, errExplain := v.c.explainConnectivityForVPC(v.src.Name(), v.dst.Name(), srcNodes, dstNodes,
			srcDstInternalAddr{false, false}, nil, connectivity)
		if errExplain != nil {
			return nil, errExplain
		}
		multiExplanation[i] = explain
	}
	return multiExplanation, nil
}

// given an Endpoint, return []Node which is either:
// 1. A single Node representing a VSI if the endpoints consists a single vsi
// 2. A number of Nodes, each representing an external address, if the endpoint is groupedExternalNodes
// if the endpoint is neither, returns error
func getNodesFromEndpoint(endpoint EndpointElem) ([]Node, error) {
	switch n := endpoint.(type) {
	case InternalNodeIntf:
		return []Node{endpoint.(Node)}, nil
	case *groupedExternalNodes:
		externalNodes := make([]Node, len(*n))
		for i, e := range *n {
			externalNodes[i] = e
		}
		return externalNodes, nil
	}
	return nil, fmt.Errorf("np-Guard error: %v not of type InternalNodeIntf or groupedExternalNodes", endpoint.Name())
}
