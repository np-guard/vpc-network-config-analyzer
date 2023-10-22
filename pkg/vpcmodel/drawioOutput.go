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
// It build the drawio tree out of the CloudConfig and VPCConnectivity, and output it to a drawio file
// the steps of creating the drawio tree:
// 1. collect all the connectivity edges to a map of (src,dst,label) -> isDirected. also mark the nodes that has connections
// 2. create the treeNodes of the NodeSets, filters. routers and nodes
// 3. create the edges from the map we created in stage (1). also also set the routers to the edges

type DrawioOutputFormatter struct {
	cConfig    *CloudConfig
	conn       *GroupConnLines
	gen        *DrawioGenerator
	subnetMode bool
	routers    map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface
}

func (d *DrawioOutputFormatter) init(cConfig *CloudConfig, conn *GroupConnLines, subnetMode bool) {
	d.cConfig = cConfig
	d.conn = conn
	d.subnetMode = subnetMode
	d.gen = NewDrawioGenerator(cConfig.CloudName)
	d.gen.network.SubnetMode = subnetMode
	d.routers = map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface{}
}

func (d *DrawioOutputFormatter) writeOutputGeneric(cConfig *CloudConfig, conn *GroupConnLines, outFile string, subnetMode bool) (
	string, error) {
	d.init(cConfig, conn, subnetMode)
	d.createDrawioTree()
	err := drawio.CreateDrawioConnectivityMapFile(d.gen.Network(), outFile)
	return "", err
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
		if !d.subnetMode || ns.ShowOnSubnetMode() {
			d.gen.TreeNode(ns)
		}
	}
}

func (d *DrawioOutputFormatter) createNodes() {
	for _, n := range d.cConfig.Nodes {
		if !n.IsExternal() && (!d.subnetMode || n.ShowOnSubnetMode()) {
			d.gen.TreeNode(n)
		}
	}
}

func (d *DrawioOutputFormatter) createFilters() {
	for _, fl := range d.cConfig.FilterResources {
		if !d.subnetMode || fl.ShowOnSubnetMode() {
			d.gen.TreeNode(fl)
		}
	}
}

func (d *DrawioOutputFormatter) createRouters() {
	for _, r := range d.cConfig.RoutingResources {
		if !d.subnetMode || r.ShowOnSubnetMode() {
			rTn := d.gen.TreeNode(r)
			for _, ni := range r.Src() {
				if !d.subnetMode || ni.ShowOnSubnetMode() {
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
		src := line.Src
		dst := line.Dst
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
		if !d.subnetMode || ei.ShowOnSubnetMode() {
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

func (d *DrawioOutputFormatter) WriteOutputAllEndpoints(cConfig *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (string, error) {
	var gConn *GroupConnLines 
	if conn != nil{
		gConn = conn.GroupedConnectivity
	}
	return d.writeOutputGeneric(cConfig, gConn, outFile, false)
}
func (d *DrawioOutputFormatter) WriteOutputAllSubnets(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	var gConn *GroupConnLines 
	if subnetsConn != nil{
		gConn = subnetsConn.GroupedConnectivity
	}
	return d.writeOutputGeneric(subnetsConn.CloudConfig, gConn, outFile, true)
}

func (d *DrawioOutputFormatter) WriteOutputSingleSubnet(c *CloudConfig, outFile string) (string, error) {
	return "", errors.New("DebugSubnet use case not supported for draw.io format currently ")
}

// /////////////////////////////////////////////////////////////////
// ArchDrawioOutputFormatter display only the architecture
// So we omit the connectivity, so we send nil to write output.
// (In archDrawio format we do not call GetVPCNetworkConnectivity, and conn should be nil,
// However, in Testing GetVPCNetworkConnectivity is called for all formats)
type ArchDrawioOutputFormatter struct {
	DrawioOutputFormatter
}

func (d *ArchDrawioOutputFormatter) WriteOutputAllEndpoints(
	cConfig *CloudConfig,
	conn *VPCConnectivity,
	outFile string,
	grouping bool) (string, error) {
	return d.DrawioOutputFormatter.WriteOutputAllEndpoints(cConfig, nil, outFile, grouping)
}

func (d *ArchDrawioOutputFormatter) WriteOutputAllSubnets(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	return d.DrawioOutputFormatter.WriteOutputAllSubnets(nil, outFile)
}

func (d *ArchDrawioOutputFormatter) WriteOutputSingleSubnet(c *CloudConfig, outFile string) (string, error) {
	return d.DrawioOutputFormatter.WriteOutputSingleSubnet(nil, outFile)
}
