package vpcmodel

import (
	"errors"

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
// It build the drawio tree out of the VPCConfig and VPCConnectivity, and output it to a drawio file
// the steps of creating the drawio tree:
// 1. collect all the connectivity edges to a map of (src,dst,label) -> isDirected. also mark the nodes that has connections
// 2. create the treeNodes of the NodeSets, filters. routers and nodes
// 3. create the edges from the map we created in stage (1). also also set the routers to the edges

type DrawioOutputFormatter struct {
	cConfig    *VPCConfig
	conn       *GroupConnLines
	gen        *DrawioGenerator
	subnetMode bool
	routers    map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface
}

func (d *DrawioOutputFormatter) init(cConfig *VPCConfig, conn *GroupConnLines, subnetMode bool) {
	d.cConfig = cConfig
	d.conn = conn
	d.subnetMode = subnetMode
	d.gen = NewDrawioGenerator(cConfig.CloudName)
	d.gen.network.SubnetMode = subnetMode
	d.routers = map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface{}
}

func (d *DrawioOutputFormatter) writeOutputGeneric(outFile string) (
	*SingleAnalysisOutput, error) {
	d.createDrawioTree()
	err := drawio.CreateDrawioConnectivityMapFile(d.gen.Network(), outFile)
	return &SingleAnalysisOutput{}, err
}

func (d *DrawioOutputFormatter) createDrawioTree() {
	d.createNodeSets()
	if !d.subnetMode {
		d.createNodes()
		d.createFilters()
	}
	d.createRouters()
	if d.conn != nil {
		d.createEdges()
	}
}

func (d *DrawioOutputFormatter) createNodeSets() {
	for _, ns := range d.cConfig.NodeSets {
		if d.showResource(ns) {
			d.gen.TreeNode(ns)
		}
	}
}

func (d *DrawioOutputFormatter) createNodes() {
	for _, n := range d.cConfig.Nodes {
		if !n.IsExternal() && d.showResource(n) {
			d.gen.TreeNode(n)
		}
	}
}

func (d *DrawioOutputFormatter) createFilters() {
	for _, fl := range d.cConfig.FilterResources {
		if d.showResource(fl) {
			d.gen.TreeNode(fl)
		}
	}
}

func (d *DrawioOutputFormatter) createRouters() {
	for _, r := range d.cConfig.RoutingResources {
		if d.showResource(r) {
			rTn := d.gen.TreeNode(r)
			for _, ni := range r.Src() {
				if d.showResource(ni) {
					d.routers[d.gen.TreeNode(ni)] = rTn.(drawio.IconTreeNodeInterface)
				}
			}
		}
	}
}

func (d *DrawioOutputFormatter) createEdges() {
	type edgeKey struct {
		src   EndpointElem
		dst   EndpointElem
		label string
	}
	isEdgeDirected := map[edgeKey]bool{}
	for _, line := range d.conn.GroupedLines {
		src := line.src
		dst := line.dst
		e := edgeKey{src, dst, line.ConnLabel()}
		revE := edgeKey{dst, src, line.ConnLabel()}
		_, revExist := isEdgeDirected[revE]
		if revExist {
			isEdgeDirected[revE] = false
		} else {
			isEdgeDirected[e] = true
		}
	}
	for e, directed := range isEdgeDirected {
		ei := &edgeInfo{e.src, e.dst, e.label, directed}
		if d.showResource(ei) {
			cn := d.gen.TreeNode(ei).(*drawio.ConnectivityTreeNode)
			if d.routers[cn.Src()] != nil && e.dst.IsExternal() {
				cn.SetRouter(d.routers[cn.Src()], false)
			}
			if d.routers[cn.Dst()] != nil && e.src.IsExternal() {
				cn.SetRouter(d.routers[cn.Dst()], true)
			}
		}
	}
}

func (d *DrawioOutputFormatter) showResource(res DrawioResourceIntf) bool {
	return !d.subnetMode || res.ShowOnSubnetMode()
}

func (d *DrawioOutputFormatter) WriteOutput(c1, c2 *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase) (*SingleAnalysisOutput, error) {
	var err error
	switch uc {
	case AllEndpoints:
		var gConn *GroupConnLines
		if conn != nil {
			gConn = conn.GroupedConnectivity
		}
		d.init(c1, gConn, false)
		return d.writeOutputGeneric(outFile)
	case AllSubnets:
		var gConn *GroupConnLines
		if subnetsConn != nil {
			gConn = subnetsConn.GroupedConnectivity
		}
		d.init(subnetsConn.VPCConfig, gConn, true)
		return d.writeOutputGeneric(outFile)
	case SingleSubnet:
		return &SingleAnalysisOutput{}, errors.New("SingleSubnet use case not supported for draw.io format currently ")
	default:
		return &SingleAnalysisOutput{}, errors.New("Use case is not currently supported for draw.io format")
	}
	return &SingleAnalysisOutput{}, err
}

// /////////////////////////////////////////////////////////////////
// ArchDrawioOutputFormatter display only the architecture
// So we omit the connectivity, so we send nil to write output.
// (In archDrawio format we do not call GetVPCNetworkConnectivity, and conn should be nil,
// However, in Testing GetVPCNetworkConnectivity is called for all formats)
type ArchDrawioOutputFormatter struct {
	DrawioOutputFormatter
}

func (d *ArchDrawioOutputFormatter) WriteOutput(c1, c2 *VPCConfig,
	conn *VPCConnectivity,
	subnetsConn *VPCsubnetConnectivity,
	cfgsDiff *diffBetweenCfgs,
	outFile string,
	grouping bool,
	uc OutputUseCase) (*SingleAnalysisOutput, error) {
		return d.DrawioOutputFormatter.WriteOutput(c1, c2, nil, nil, nil, outFile, grouping, uc)
}
