package vpcmodel

import (
	"errors"

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
	cConfigs        map[string]*VPCConfig
	conns           map[string]*GroupConnLines
	gen             *DrawioGenerator
	nodeRouters     map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface
	multiVpcRouters map[string]drawio.IconTreeNodeInterface
	uc              OutputUseCase
}

func (d *DrawioOutputFormatter) init(cConfigs map[string]*VPCConfig, conns map[string]*GroupConnLines, uc OutputUseCase) {
	d.cConfigs = cConfigs
	d.conns = conns
	d.uc = uc
	// just take the cloud name from one of the configs
	_, aVpcConfig := common.AnyMapEntry(cConfigs)
	cloudName := aVpcConfig.CloudName
	d.gen = NewDrawioGenerator(cloudName)
	d.nodeRouters = map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface{}
	d.multiVpcRouters = map[string]drawio.IconTreeNodeInterface{}
}

func (d *DrawioOutputFormatter) createDrawioTree() {
	d.createNodeSets()
	if d.uc != AllSubnets {
		// todo - support filters on subnet mode
		d.createNodes()
		d.createFilters()
	}
	d.createRouters()
	if d.conns != nil {
		d.createEdges()
	}
}

func (d *DrawioOutputFormatter) createNodeSets() {
	for _, vpcConfig := range d.cConfigs {
		if !vpcConfig.IsMultipleVPCsConfig {
			for _, ns := range vpcConfig.NodeSets {
				if d.showResource(ns) {
					d.gen.TreeNode(ns)
				}
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
					for _, ni := range r.Src() {
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
	switch {
	case d.cConfigs[vpcResourceName].IsMultipleVPCsConfig:
		return d.multiVpcRouters[vpcResourceName]
	case line.dst.IsExternal():
		return d.nodeRouters[d.gen.TreeNode(line.src)]
	case line.src.IsExternal():
		return d.nodeRouters[d.gen.TreeNode(line.dst)]
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
	for vpcResourceName, vpcConn := range d.conns {
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
				cn.SetRouter(e.router, e.src.IsExternal())
			}
		}
	}
}

func (d *DrawioOutputFormatter) showResource(res DrawioResourceIntf) bool {
	return d.uc != AllSubnets || res.ShowOnSubnetMode()
}

func (d *DrawioOutputFormatter) WriteOutput(c1, c2 map[string]*VPCConfig,
	conn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase) (string, error) {
	switch uc {
	case AllEndpoints:
		gConn := map[string]*GroupConnLines{}
		for name, vpcConn := range conn {
			gConn[name] = vpcConn.GroupedConnectivity
		}
		d.init(c1, gConn, uc)
	case AllSubnets:
		gConfigs := map[string]*VPCConfig{}
		gConn := map[string]*GroupConnLines{}
		if subnetsConn != nil {
			for name, vpcConn := range subnetsConn {
				gConn[name] = vpcConn.GroupedConnectivity
				gConfigs[name] = vpcConn.VPCConfig
			}
		} else {
			gConfigs = c1
		}
		d.init(gConfigs, gConn, uc)
	default:
		return "", errors.New("use case is not currently supported for draw.io format")
	}
	d.createDrawioTree()
	return "", drawio.CreateDrawioConnectivityMapFile(d.gen.Network(), outFile, d.uc == AllSubnets)
}

// /////////////////////////////////////////////////////////////////
// ArchDrawioOutputFormatter display only the architecture
// So we omit the connectivity, so we send nil to write output.
// (In archDrawio format we do not call GetVPCNetworkConnectivity, and conn should be nil,
// However, in Testing GetVPCNetworkConnectivity is called for all formats)
type ArchDrawioOutputFormatter struct {
	DrawioOutputFormatter
}

func (d *ArchDrawioOutputFormatter) WriteOutput(c1, c2 map[string]*VPCConfig,
	conn map[string]*VPCConnectivity,
	subnetsConn map[string]*VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase) (string, error) {
	return d.DrawioOutputFormatter.WriteOutput(c1, c2, nil, nil, nil, outFile, grouping, uc)
}
