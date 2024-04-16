/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import "fmt"

type srcDstEndPoint struct {
	c   *VPCConfig
	src EndpointElem
	dst EndpointElem
}

type extendedExplain struct {
	explain *Explanation
	err     error
}

// MultiExplain multi-explanation mode: given a slice of <VPCConfig, Endpoint, Endpoint> such that each Endpoint is either
// a vsi or grouped external addresses of the given config, returns []extendedExplain where item i provides explaination to input i
func MultiExplain(srcDstCouples []srcDstEndPoint) (multiExplaination []extendedExplain, err error) {
	multiExplaination = make([]extendedExplain, len(srcDstCouples))
	vpcsConnects := map[string]*VPCConnectivity{}
	for i, v := range srcDstCouples {
		emptyExplain := &Explanation{nil, nil, nil, v.src.Name(), v.dst.Name(),
			nil, nil, false, nil}
		if v.c == nil {
			// no vpc config implies missing cross-vpc router between src and dst which are not in the same VPC
			multiExplaination[i] = extendedExplain{emptyExplain, nil}
			continue
		}
		srcNodes, errSrc := getNodesFromEndpoint(v.src)
		if errSrc != nil {
			multiExplaination[i] = extendedExplain{emptyExplain, errSrc}
			continue
		}
		dstNodes, errDst := getNodesFromEndpoint(v.dst)
		if errSrc != nil {
			multiExplaination[i] = extendedExplain{emptyExplain, errDst}
			continue
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
		multiExplaination[i] = extendedExplain{explain, nil}
	}
	return multiExplaination, nil
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
