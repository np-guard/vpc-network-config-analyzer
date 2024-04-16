/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"errors"
	"slices"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
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

// DrawioOutputFormatter create the drawio connectivity map.
// It builds the drawio tree out of the VPCConfigs and VPCConnectivitys, and outputs it to a drawio file
// the steps of creating the drawio tree:
// 1. collect all the connectivity edges to a map of (src,dst,label) -> isDirected. also mark the nodes that has connections
// 2. create the treeNodes of the NodeSets, filters. routers and nodes
// 3. create the edges from the map we created in stage (1). also sets the routers to the edges

type DrawioOutputFormatter struct {
	cConfigs        MultipleVPCConfigs
	vpcConns        map[string]*VPCConnectivity
	gConns          map[string]*GroupConnLines
	gen             *DrawioGenerator
	nodeRouters     map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface
	multiVpcRouters map[string]drawio.IconTreeNodeInterface
	uc              OutputUseCase
	outFormat       OutFormat
}

func newDrawioOutputFormatter(outFormat OutFormat) *DrawioOutputFormatter {
	d := DrawioOutputFormatter{}
	d.outFormat = outFormat
	d.nodeRouters = map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface{}
	d.multiVpcRouters = map[string]drawio.IconTreeNodeInterface{}
	return &d
}
func (d *DrawioOutputFormatter) init(cConfigs MultipleVPCConfigs, vpcConns map[string]*VPCConnectivity, gConns map[string]*GroupConnLines, uc OutputUseCase) {
	d.cConfigs = cConfigs
	d.vpcConns = vpcConns
	d.gConns = gConns
	d.uc = uc
	// just take the cloud name from one of the configs
	_, aVpcConfig := common.AnyMapEntry(cConfigs)
	cloudName := aVpcConfig.CloudName
	d.gen = NewDrawioGenerator(cloudName)
}

func (d *DrawioOutputFormatter) createDrawioTree() {
	d.createNodeSets()
	if d.uc != AllSubnets {
		// todo - support filters on subnet mode
		d.createNodes()
		d.createFilters()
	}
	d.createRouters()
	if d.gConns != nil {
		d.createEdges()
	}
}

func (d *DrawioOutputFormatter) createNodeSets() {
	for _, vpcConfig := range d.cConfigs {
		if vpcConfig.IsMultipleVPCsConfig {
			continue
		}
		// vpc
		if d.showResource(vpcConfig.VPC) {
			d.gen.TreeNode(vpcConfig.VPC)
		}
		// subnets
		for _, ns := range vpcConfig.Subnets {
			if d.showResource(ns) {
				d.gen.TreeNode(ns)
			}
		}
		for _, lb := range vpcConfig.LoadBalancers {
			if d.showResource(lb) {
				d.gen.TreeNode(lb)
			}
		}
		// nodesets (vsi, vpe)
		for _, ns := range vpcConfig.NodeSets {
			if d.showResource(ns) {
				d.gen.TreeNode(ns)
			}
		}
	}
}

func (d *DrawioOutputFormatter) createNodes() {
	for _, vpcConfig := range d.cConfigs {
		if !vpcConfig.IsMultipleVPCsConfig {
			for _, n := range vpcConfig.Nodes {
				if !n.IsExternal() && d.showResource(n) {
					d.gen.TreeNode(n)
				}
			}
		}
	}
}

func (d *DrawioOutputFormatter) createFilters() {
	for _, vpcConfig := range d.cConfigs {
		if !vpcConfig.IsMultipleVPCsConfig {
			for _, fl := range vpcConfig.FilterResources {
				if d.showResource(fl) {
					d.gen.TreeNode(fl)
				}
			}
		}
	}
}

func (d *DrawioOutputFormatter) createRouters() {
	for vpcResourceName, vpcConfig := range d.cConfigs {
		for _, r := range vpcConfig.RoutingResources {
			if d.showResource(r) {
				rTn := d.gen.TreeNode(r)
				if vpcConfig.IsMultipleVPCsConfig {
					d.multiVpcRouters[vpcResourceName] = rTn.(drawio.IconTreeNodeInterface)
				} else {
					for _, ni := range r.Sources() {
						if d.showResource(ni) {
							d.nodeRouters[d.gen.TreeNode(ni)] = rTn.(drawio.IconTreeNodeInterface)
						}
					}
				}
			}
		}
	}
}

func (d *DrawioOutputFormatter) lineRouter(line *groupedConnLine, vpcResourceName string) drawio.IconTreeNodeInterface {
	if d.cConfigs[vpcResourceName].IsMultipleVPCsConfig {
		return d.multiVpcRouters[vpcResourceName]
	}
	var routeredEP EndpointElem
	switch {
	case line.dst.IsExternal():
		routeredEP = line.src
	case line.src.IsExternal():
		routeredEP = line.dst
	default:
		return nil
	}
	if group, ok := routeredEP.(*groupedEndpointsElems); ok {
		firstRouter := d.nodeRouters[d.gen.TreeNode((*group)[0])]
		for _, node := range *group {
			if d.nodeRouters[d.gen.TreeNode(node)] != firstRouter {
				return nil
			}
		}
		return firstRouter
	}
	return nil
}

func (d *DrawioOutputFormatter) createEdges() {
	type edgeKey struct {
		src    EndpointElem
		dst    EndpointElem
		router drawio.IconTreeNodeInterface
		label  string
	}
	isEdgeDirected := map[edgeKey]bool{}
	for vpcResourceName, vpcConn := range d.gConns {
		for _, line := range vpcConn.GroupedLines {
			src := line.src
			dst := line.dst
			router := d.lineRouter(line, vpcResourceName)
			e := edgeKey{src, dst, router, line.ConnLabel()}
			revE := edgeKey{dst, src, router, line.ConnLabel()}
			_, revExist := isEdgeDirected[revE]
			if revExist {
				isEdgeDirected[revE] = false
			} else {
				isEdgeDirected[e] = true
			}
		}
	}
	for e, directed := range isEdgeDirected {
		ei := &edgeInfo{e.src, e.dst, e.label, directed}
		if d.showResource(ei) {
			cn := d.gen.TreeNode(ei).(*drawio.ConnectivityTreeNode)
			if e.router != nil {
				cn.SetRouter(e.router)
			}
		}
	}
}

func (d *DrawioOutputFormatter) createExplanations() []drawio.ExplanationEntry {
	if d.outFormat != HTML {
		return nil
	}
	explanationsInput := CreateMultiExplanationsInput(d.cConfigs, d.gConns)
	explanationsInput = slices.DeleteFunc(explanationsInput, func(e srcDstEndPoint) bool {
		return !d.showResource(e.src) || !d.showResource(e.dst)
	})

	explanations := MultiExplain(explanationsInput, d.vpcConns)
	explanationsTests := make([]drawio.ExplanationEntry, len(explanations))
	for i, e := range explanations {
		explanationsTests[i] = drawio.ExplanationEntry{Src: d.gen.TreeNode(explanationsInput[i].src), Dst: d.gen.TreeNode(explanationsInput[i].dst), Text: e.String()}
	}
	return explanationsTests
}

func (d *DrawioOutputFormatter) showResource(res DrawioResourceIntf) bool {
	return d.uc != AllSubnets || res.ShowOnSubnetMode()
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

func (d *DrawioOutputFormatter) WriteOutput(c1, c2 MultipleVPCConfigs,
	conn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase,
	explanation *Explanation) (string, error) {
	switch uc {
	case AllEndpoints:
		gConn := map[string]*GroupConnLines{}
		for name, vpcConn := range conn {
			gConn[name] = vpcConn.GroupedConnectivity
		}
		d.init(c1, conn, gConn, uc)
	case AllSubnets:
		gConfigs := MultipleVPCConfigs{}
		gConn := map[string]*GroupConnLines{}
		if subnetsConn != nil {
			for name, vpcConn := range subnetsConn {
				gConn[name] = vpcConn.GroupedConnectivity
				gConfigs[name] = vpcConn.VPCConfig
			}
		} else {
			gConfigs = c1
		}
		d.init(gConfigs, conn, gConn, uc)
	default:
		return "", errors.New("use case is not currently supported for draw.io format")
	}
	d.createDrawioTree()
	return "", drawio.CreateDrawioConnectivityMapFile(d.gen.Network(), outFile, d.uc == AllSubnets, d.drawioFormat(), d.createExplanations())
}

// /////////////////////////////////////////////////////////////////
// ArchDrawioOutputFormatter display only the architecture
// So we omit the connectivity, so we send nil to write output.
// (In archDrawio format we do not call GetVPCNetworkConnectivity, and conn should be nil,
// However, in Testing GetVPCNetworkConnectivity is called for all formats)
type ArchDrawioOutputFormatter struct {
	DrawioOutputFormatter
}

func newArchDrawioOutputFormatter(outFormat OutFormat) *ArchDrawioOutputFormatter {
	return &ArchDrawioOutputFormatter{*newDrawioOutputFormatter(outFormat)}
}
func (d *ArchDrawioOutputFormatter) WriteOutput(c1, c2 MultipleVPCConfigs,
	conn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase,
	explanation *Explanation) (string, error) {
	return d.DrawioOutputFormatter.WriteOutput(c1, c2, nil, nil, nil, outFile, grouping, uc, explanation)
}
