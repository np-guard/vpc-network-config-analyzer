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

func (e *extendedExplain) String() string {
	if e.err != nil {
		return e.err.Error()
	}
	return e.explain.String(true)
}

// MultiExplain multi-explanation mode: given a slice of <VPCConfig, Endpoint, Endpoint> such that each Endpoint is either
// a vsi or grouped external addresses of the given config, returns []extendedExplain where item i provides explaination to input i
func MultiExplain(srcDstCouples []srcDstEndPoint, vpcConns map[string]*VPCConnectivity) []extendedExplain {
	multiExplanation := make([]extendedExplain, len(srcDstCouples))
	for i, v := range srcDstCouples {
		emptyExplain := &Explanation{nil, nil, nil, v.src.Name(), v.dst.Name(),
			nil, nil, false, nil}
		if v.c == nil {
			// no vpc config implies missing cross-vpc router between src and dst which are not in the same VPC
			multiExplanation[i] = extendedExplain{emptyExplain, nil}
			continue
		}
		srcNodes, errSrc := getNodesFromEndpoint(v.src)
		if errSrc != nil {
			multiExplanation[i] = extendedExplain{emptyExplain, errSrc}
			continue
		}
		dstNodes, errDst := getNodesFromEndpoint(v.dst)
		if errSrc != nil {
			multiExplanation[i] = extendedExplain{emptyExplain, errDst}
			continue
		}
		var connectivity *VPCConnectivity
		var ok bool
		if connectivity, ok = vpcConns[v.c.VPC.Name()]; !ok {
			errConn := fmt.Errorf("npGuard eror: missing connectivity computation for %v in MultiExplain", v.c.VPC.Name())
			multiExplanation[i] = extendedExplain{emptyExplain, errConn}
			continue
		}
		explain, errExplain := v.c.explainConnectivityForVPC(v.src.Name(), v.dst.Name(), srcNodes, dstNodes,
			srcDstInternalAddr{false, false}, nil, connectivity)
		if errExplain != nil {
			multiExplanation[i] = extendedExplain{emptyExplain, errExplain}
			continue
		}
		multiExplanation[i] = extendedExplain{explain, nil}
	}
	return multiExplanation
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

func createMultiExplanationsInput(cConfigs MultipleVPCConfigs, conns map[string]*GroupConnLines) []srcDstEndPoint {
	multiVpcEndpoints := map[EndpointElem]map[EndpointElem]*VPCConfig{}
	externalNodes := map[EndpointElem]bool{}
	internalNodes := map[EndpointElem]*VPCConfig{}
	for _, vpcConfig := range cConfigs {
		if !vpcConfig.IsMultipleVPCsConfig {
			for _, n := range vpcConfig.Nodes {
				if !n.IsExternal() {
					internalNodes[n] = vpcConfig
				}
			}
		}
	}
	for _, vpcConn := range conns {
		for _, line := range vpcConn.GroupedLines {
			if eSrc, ok := line.src.(*groupedExternalNodes); ok {
				externalNodes[eSrc] = true
			}
			if eDst, ok := line.dst.(*groupedExternalNodes); ok {
				externalNodes[eDst] = true
			}
		}
	}
	for vpcName, vpcConfig := range cConfigs {
		if vpcConfig.IsMultipleVPCsConfig {
			vpcConn := conns[vpcName]
			for _, line := range vpcConn.GroupedLines {
				srcs := []EndpointElem{line.src}
				dsts := []EndpointElem{line.dst}
				if srcList, ok := line.src.(*groupedEndpointsElems); ok {
					srcs = *srcList
				}
				if dstList, ok := line.dst.(*groupedEndpointsElems); ok {
					dsts = *dstList
				}
				for _, src := range srcs {
					for _, dst := range dsts {
						if _, ok := multiVpcEndpoints[src]; !ok {
							multiVpcEndpoints[src] = map[EndpointElem]*VPCConfig{}
						}
						multiVpcEndpoints[src][dst] = vpcConfig
					}
				}
			}
		}
	}
	explanationsInput := []srcDstEndPoint{}
	for src, srcConfig := range internalNodes {
		for dst, dstConfig := range internalNodes {
			var vpcConfig *VPCConfig
			if multiVpcConfig, ok := multiVpcEndpoints[src][dst]; ok {
				vpcConfig = multiVpcConfig
			} else if srcConfig == dstConfig {
				vpcConfig = srcConfig
			}
			explanationsInput = append(explanationsInput, srcDstEndPoint{vpcConfig, src, dst})
		}
		for external := range externalNodes {
			explanationsInput = append(explanationsInput, srcDstEndPoint{srcConfig, src, external})
			explanationsInput = append(explanationsInput, srcDstEndPoint{srcConfig, external, src})
		}
	}
	return explanationsInput
}
