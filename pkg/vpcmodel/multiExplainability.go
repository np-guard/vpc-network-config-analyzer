/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"

	"github.com/np-guard/models/pkg/ipblock"
)

type explainInputEntry struct {
	c   *VPCConfig
	src EndpointElem
	dst EndpointElem
}

type explainOutputEntry struct {
	explain *Explanation
	err     error
}

func (e *explainOutputEntry) String() string {
	if e.err != nil {
		return e.err.Error()
	}
	return e.explain.String(true)
}

func (e *explainOutputEntry) EntryError() string {
	if e.err != nil {
		return e.err.Error()
	}
	return ""
}

// MultiExplain multi-explanation mode: given a slice of <VPCConfig, Endpoint, Endpoint> such that each Endpoint is either
// a vsi or grouped external addresses of the given config, returns []explainOutputEntry where item i provides explanation to input i
func MultiExplain(srcDstCouples []explainInputEntry, vpcConns map[string]*VPCConnectivity) []explainOutputEntry {
	multiExplanation := make([]explainOutputEntry, len(srcDstCouples))
	for i, srcDstCouple := range srcDstCouples {
		emptyExplain := &Explanation{
			src: srcDstCouple.src.NameForAnalyzerOut(nil),
			dst: srcDstCouple.dst.NameForAnalyzerOut(nil),
		}
		if srcDstCouple.c == nil {
			// no vpc config implies missing cross-vpc router between src and dst which are not in the same VPC
			multiExplanation[i] = explainOutputEntry{emptyExplain, nil}
			continue
		}
		srcNodes, errSrc := getNodesFromEndpoint(srcDstCouple.c, srcDstCouple.src)
		if errSrc != nil {
			multiExplanation[i] = explainOutputEntry{emptyExplain, errSrc}
			continue
		}
		dstNodes, errDst := getNodesFromEndpoint(srcDstCouple.c, srcDstCouple.dst)
		if errDst != nil {
			multiExplanation[i] = explainOutputEntry{emptyExplain, errDst}
			continue
		}
		emptyExplain.srcNodes, emptyExplain.dstNodes = srcNodes, dstNodes
		var connectivity *VPCConnectivity
		var ok bool
		if connectivity, ok = vpcConns[srcDstCouple.c.VPC.UID()]; !ok {
			errConn := fmt.Errorf("npGuard eror: missing connectivity computation for %v %v in MultiExplain",
				srcDstCouple.c.VPC.UID(), srcDstCouple.c.VPC.Name())
			multiExplanation[i] = explainOutputEntry{emptyExplain, errConn}
			continue
		}
		explain, errExplain := explainConnectivityForVPC(srcDstCouple.c, srcDstCouple.src.NameForAnalyzerOut(nil),
			srcDstCouple.dst.NameForAnalyzerOut(nil),
			srcNodes, dstNodes, nil, connectivity)
		if errExplain != nil {
			multiExplanation[i] = explainOutputEntry{emptyExplain, errExplain}
			continue
		}
		multiExplanation[i] = explainOutputEntry{explain, nil}
	}
	return multiExplanation
}

// given an EndpointElem, return []Node which is either:
// 1. A single Node representing a VSI if the endpoints consists a single vsi
// 2. A number of Nodes, all are private IPs of the load Balancer
// 2. A number of Nodes, each representing an external address, if the endpoint is groupedExternalNodes
// if the endpoint is neither, returns error
func getNodesFromEndpoint(c *VPCConfig, endpoint EndpointElem) ([]Node, error) {
	switch n := endpoint.(type) {
	case InternalNodeIntf:
		return []Node{endpoint.(Node)}, nil
	case LoadBalancer:
		return n.Nodes(), nil
	case *groupedExternalNodes:
		var externalIP = ipblock.New()
		for _, e := range *n {
			externalIP = externalIP.Union(e.ipblock)
		}
		// gets external nodes from e as explained in getCidrExternalNodes
		disjointNodes, _, err := getCidrExternalNodes(c, externalIP)
		if err != nil {
			return nil, err
		}
		return disjointNodes, nil
	}
	return nil, fmt.Errorf("np-Guard error: %v not of type InternalNodeIntf or groupedExternalNodes", endpoint.NameForAnalyzerOut(nil))
}

// CreateMultiExplanationsInput given configs and results of connectivity analysis, generates input
// in the format required by MultiExplain
// it creates the explainInputEntry of all the following cases:
// (1) src and dst are internal nodes from the same vpc:                                 {src,dst,vpcConfig}
// (2) src is internal and dst is external:                                              {src,dst,srcVpcConfig}
// (3) dst is internal and src is external:                                              {src,dst,dstVpcConfig}
// (4) src and dst are internal nodes from different vpcs and has a multivpc connection: {src,dst,multiVpcConfig}
// (5) src and dst are internal nodes from different vpcs and has no connection:         {src,dst,nil}
func CreateMultiExplanationsInput(
	cConfigs *MultipleVPCConfigs,
	vpcConns map[string]*VPCConnectivity,
	gConns map[string]*GroupConnLines) []explainInputEntry {
	internalNodes, externalNodes := collectNodesForExplanation(cConfigs, gConns)
	multiVpcConnections := collectMultiConnectionsForExplanation(cConfigs, vpcConns)
	explanationsInput := []explainInputEntry{}
	for src, srcConfig := range internalNodes {
		for dst, dstConfig := range internalNodes {
			var vpcConfig *VPCConfig
			if multiVpcConfig, ok := multiVpcConnections[src][dst]; ok {
				vpcConfig = multiVpcConfig // input of case (4)
			} else if srcConfig == dstConfig {
				vpcConfig = srcConfig // input of case (1)
			} // else - input of case (5)
			explanationsInput = append(explanationsInput, explainInputEntry{vpcConfig, src, dst})
		}
		for external := range externalNodes {
			explanationsInput = append(explanationsInput,
				explainInputEntry{srcConfig, src, external}, // input of case (2)
				explainInputEntry{srcConfig, external, src}) // input of case (3)
		}
	}
	return explanationsInput
}

func collectNodesForExplanation(cConfigs *MultipleVPCConfigs, conns map[string]*GroupConnLines) (
	internalNodes map[EndpointElem]*VPCConfig, externalNodes map[EndpointElem]bool) {
	internalNodes = map[EndpointElem]*VPCConfig{}
	externalNodes = map[EndpointElem]bool{}
	for _, vpcConfig := range cConfigs.Configs() {
		if !vpcConfig.IsMultipleVPCsConfig {
			for _, n := range vpcConfig.Nodes {
				if !n.IsExternal() {
					if abstractedToNodeSet := n.AbstractedToNodeSet(); abstractedToNodeSet != nil {
						internalNodes[abstractedToNodeSet] = vpcConfig
					} else {
						internalNodes[n] = vpcConfig
					}
				}
			}
		}
	}
	// we collect only external nodes with connections:
	for _, vpcConn := range conns {
		for _, line := range vpcConn.GroupedLines {
			if eSrc, ok := line.Src.(*groupedExternalNodes); ok {
				externalNodes[eSrc] = true
			}
			if eDst, ok := line.Dst.(*groupedExternalNodes); ok {
				externalNodes[eDst] = true
			}
		}
	}
	if cConfigs.publicNetworkNode != nil {
		externalNodes[cConfigs.publicNetworkNode] = true
	}
	return internalNodes, externalNodes
}

func collectMultiConnectionsForExplanation(
	cConfigs *MultipleVPCConfigs, conns map[string]*VPCConnectivity) map[EndpointElem]map[EndpointElem]*VPCConfig {
	multiVpcConnections := map[EndpointElem]map[EndpointElem]*VPCConfig{}
	for vpcUID, vpcConfig := range cConfigs.Configs() {
		if vpcConfig.IsMultipleVPCsConfig {
			for src, dsts := range conns[vpcUID].AllowedConnsCombinedResponsive {
				for dst := range dsts {
					if _, ok := multiVpcConnections[src]; !ok {
						multiVpcConnections[src] = map[EndpointElem]*VPCConfig{}
					}
					multiVpcConnections[src][dst] = vpcConfig
				}
			}
		}
	}
	return multiVpcConnections
}
