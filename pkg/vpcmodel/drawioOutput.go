/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"errors"
	"slices"
	"strings"

	"github.com/np-guard/models/pkg/spec"
	common "github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

type edgeInfo struct {
	src      EndpointElem
	dst      EndpointElem
	label    string
	directed bool
}

func (e *edgeInfo) IsExternal() bool {
	return e.src.IsExternal() || e.dst.IsExternal()
}
func (e *edgeInfo) SynthesisResourceName() string {
	return ""
}
func (e *edgeInfo) SynthesisKind() spec.ResourceType {
	return ""
}

// DrawioOutputFormatter create the drawio connectivity map.
// It builds the drawio tree out of the VPCConfigs and VPCConnectivitys, and outputs it to a drawio file
// the steps of creating the drawio tree:
// 1. collect all the connectivity edges to a map of (src,dst,label) -> isDirected. also mark the nodes that has connections
// 2. create the treeNodes of the NodeSets, filters. routers and nodes
// 3. create the edges from the map we created in stage (1). also sets the routers to the edges

type DrawioOutputFormatter struct {
	cConfigs        *MultipleVPCConfigs
	vpcConns        map[string]*VPCConnectivity
	gConns          map[string]*GroupConnLines
	gen             *DrawioGenerator
	nodeRouters     map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface
	multiVpcRouters map[string]drawio.IconTreeNodeInterface
	uc              OutputUseCase
	outFormat       OutFormat
	lbAbstraction   bool
}

func newDrawioOutputFormatter(outFormat OutFormat, lbAbstraction bool) *DrawioOutputFormatter {
	d := DrawioOutputFormatter{}
	d.outFormat = outFormat
	d.nodeRouters = map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface{}
	d.multiVpcRouters = map[string]drawio.IconTreeNodeInterface{}
	d.lbAbstraction = lbAbstraction
	return &d
}
func (d *DrawioOutputFormatter) init(
	cConfigs *MultipleVPCConfigs,
	vpcConns map[string]*VPCConnectivity,
	gConns map[string]*GroupConnLines,
	uc OutputUseCase) {
	d.cConfigs = cConfigs
	d.vpcConns = vpcConns
	d.gConns = gConns
	d.uc = uc
	d.gen = NewDrawioGenerator(cConfigs.CloudName(), d.lbAbstraction, uc)
}

func (d *DrawioOutputFormatter) createDrawioTree() {
	d.createNodeSets()
	d.createNodes()
	d.createFilters()
	d.createRouters()
	if d.gConns != nil {
		d.createEdges()
	}
}

func (d *DrawioOutputFormatter) createNodeSets() {
	for _, vpcConfig := range d.cConfigs.Configs() {
		if vpcConfig.IsMultipleVPCsConfig {
			continue
		}
		// vpc
		d.gen.TreeNode(vpcConfig.VPC)
		// subnets
		for _, ns := range vpcConfig.Subnets {
			d.gen.TreeNode(ns)
		}
		for _, lb := range vpcConfig.LoadBalancers {
			d.gen.TreeNode(lb)
		}
		// nodesets (vsi, vpe)
		for _, ns := range vpcConfig.NodeSets {
			d.gen.TreeNode(ns)
		}
	}
}

func (d *DrawioOutputFormatter) createNodes() {
	for _, vpcConfig := range d.cConfigs.Configs() {
		if !vpcConfig.IsMultipleVPCsConfig {
			for _, n := range vpcConfig.Nodes {
				if !n.IsExternal() {
					d.gen.TreeNode(n)
				}
			}
		}
	}
}

func (d *DrawioOutputFormatter) createFilters() {
	for _, vpcConfig := range d.cConfigs.Configs() {
		if !vpcConfig.IsMultipleVPCsConfig {
			for _, fl := range vpcConfig.FilterResources {
				d.gen.TreeNode(fl)
			}
		}
	}
}

func (d *DrawioOutputFormatter) createRouters() {
	for vpcResourceID, vpcConfig := range d.cConfigs.Configs() {
		for _, r := range vpcConfig.RoutingResources {
			if r.IsMultipleVPCs() != vpcConfig.IsMultipleVPCsConfig {
				// MultipleVPCs routers might exist at a non MultipleVPCs config (and vice versa?), it should be ignored
				continue
			}
			if rTn := d.gen.TreeNode(r); rTn != nil {
				if vpcConfig.IsMultipleVPCsConfig {
					d.multiVpcRouters[vpcResourceID] = rTn.(drawio.IconTreeNodeInterface)
				} else {
					for _, ni := range r.Sources() {
						if nTn := d.gen.TreeNode(ni); nTn != nil {
							d.nodeRouters[nTn] = rTn.(drawio.IconTreeNodeInterface)
						}
					}
					if d.uc == AllSubnets {
						for _, s := range r.SourcesSubnets() {
							d.nodeRouters[d.gen.TreeNode(s)] = rTn.(drawio.IconTreeNodeInterface)
						}
					}
				}
			}
		}
	}
}

func (d *DrawioOutputFormatter) lineRouter(line *groupedConnLine, vpcResourceID string) drawio.IconTreeNodeInterface {
	if d.cConfigs.Config(vpcResourceID).IsMultipleVPCsConfig {
		return d.multiVpcRouters[vpcResourceID]
	}
	var routeredEP EndpointElem
	switch {
	case line.Dst.IsExternal():
		routeredEP = line.Src
	case line.Src.IsExternal():
		routeredEP = line.Dst
	default:
		return nil
	}
	// collecting all the routers of the EP, if it has one router, returning it
	epRouters := map[drawio.IconTreeNodeInterface]bool{}
	for _, node := range endpointElemResources(routeredEP) {
		epRouters[d.nodeRouters[d.gen.TreeNode(node)]] = true
	}
	if len(epRouters) == 1 {
		router, _ := common.AnyMapEntry(epRouters)
		return router
	}
	return nil
}

// createEdges() has three steps:
// 1. union edges that have the same src/dst/direction with different labels to one edge
// 2. union two edges with opposite direction and the same labels to one edge
// 3. creating the TreeNodes, and set the routers
func (d *DrawioOutputFormatter) createEdges() {
	// 1. union for different labels:
	type edgeKeyForLabels struct {
		src    EndpointElem
		dst    EndpointElem
		router drawio.IconTreeNodeInterface
	}
	edgeLabels := map[edgeKeyForLabels][]string{}
	for vpcResourceID, vpcConn := range d.gConns {
		for _, line := range vpcConn.GroupedLines {
			router := d.lineRouter(line, vpcResourceID)
			k := edgeKeyForLabels{line.Src, line.Dst, router}
			edgeLabels[k] = append(edgeLabels[k], line.ConnLabel(false))
		}
	}
	// 2.union for opposite direction:
	type edgeKey struct {
		src    EndpointElem
		dst    EndpointElem
		router drawio.IconTreeNodeInterface
		label  string
	}
	isEdgeDirected := map[edgeKey]bool{}
	for key, labels := range edgeLabels {
		slices.Sort(labels)
		label := strings.Join(labels, ";  ")
		e := edgeKey{key.src, key.dst, key.router, label}
		revE := edgeKey{key.dst, key.src, key.router, label}
		_, revExist := isEdgeDirected[revE]
		if revExist {
			isEdgeDirected[revE] = false
		} else {
			isEdgeDirected[e] = true
		}
	}
	// 3. create TreeNodes:
	for e, directed := range isEdgeDirected {
		ei := &edgeInfo{e.src, e.dst, e.label, directed}
		eTn := d.gen.TreeNode(ei)
		if eTn != nil && e.router != nil {
			eTn.(*drawio.ConnectivityTreeNode).SetRouter(e.router)
		}
	}
}

// createExplanations() create explanations for every pairs of nodes to be display on the canvas
func (d *DrawioOutputFormatter) createExplanations() []drawio.ExplanationEntry {
	if d.outFormat != HTML || d.uc != AllEndpoints {
		return nil
	}
	explanationsInput := CreateMultiExplanationsInput(d.cConfigs, d.vpcConns, d.gConns)
	// remove all the entries that are not shown on the canvas:
	explanationsInput = slices.DeleteFunc(explanationsInput, func(e explainInputEntry) bool {
		return d.gen.TreeNode(e.src) == nil || d.gen.TreeNode(e.dst) == nil
	})

	explanations := MultiExplain(explanationsInput, d.vpcConns)
	explanationsTests := make([]drawio.ExplanationEntry, len(explanations))
	for i, e := range explanations {
		explanationsTests[i] = drawio.ExplanationEntry{
			Src:  d.gen.TreeNode(explanationsInput[i].src),
			Dst:  d.gen.TreeNode(explanationsInput[i].dst),
			Text: e.String()}
	}
	return explanationsTests
}

func (d *DrawioOutputFormatter) drawioFormat() drawio.FileFormat {
	switch d.outFormat {
	case DRAWIO, ARCHDRAWIO:
		return drawio.FileDRAWIO
	case SVG, ARCHSVG:
		return drawio.FileSVG
	case HTML, ARCHHTML:
		return drawio.FileHTML
	}
	return drawio.FileDRAWIO
}

func (d *DrawioOutputFormatter) WriteOutput(cConfigs *MultipleVPCConfigs,
	conn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase,
	explanation *Explanation, detailExplain bool) (string, error) {
	switch uc {
	case AllEndpoints:
		gConn := map[string]*GroupConnLines{}
		for id, vpcConn := range conn {
			gConn[id] = vpcConn.GroupedConnectivity
		}
		d.init(cConfigs, conn, gConn, uc)
	case AllSubnets:
		gConfigs := NewMultipleVPCConfigs(cConfigs.Provider())
		gConn := map[string]*GroupConnLines{}
		if subnetsConn != nil {
			for id, vpcConn := range subnetsConn {
				gConn[id] = vpcConn.GroupedConnectivity
				gConfigs.SetConfig(id, vpcConn.VPCConfig)
			}
		} else {
			gConfigs = cConfigs
		}
		d.init(gConfigs, conn, gConn, uc)
	default:
		return "", errors.New("use case is not currently supported for draw.io format")
	}
	d.createDrawioTree()
	res, err := drawio.CreateDrawioConnectivityMap(d.gen.Network(), d.uc == AllSubnets,
		d.drawioFormat(), d.createExplanations(), cConfigs.Provider())
	if err != nil {
		return "", err
	}
	return WriteToFile(res, outFile)
}

// /////////////////////////////////////////////////////////////////
// ArchDrawioOutputFormatter display only the architecture
// So we omit the connectivity, so we send nil to write output.
// (In archDrawio format we do not call GetVPCNetworkConnectivity, and conn should be nil,
// However, in Testing GetVPCNetworkConnectivity is called for all formats)
type ArchDrawioOutputFormatter struct {
	DrawioOutputFormatter
}

func newArchDrawioOutputFormatter(outFormat OutFormat, lbAbstraction bool) *ArchDrawioOutputFormatter {
	return &ArchDrawioOutputFormatter{*newDrawioOutputFormatter(outFormat, lbAbstraction)}
}
func (d *ArchDrawioOutputFormatter) WriteOutput(cConfigs *MultipleVPCConfigs,
	conn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase,
	explanation *Explanation, detailExplain bool) (string, error) {
	return d.DrawioOutputFormatter.WriteOutput(cConfigs, nil, nil, nil, outFile, grouping, uc, explanation, detailExplain)
}
