package vpcmodel

import (
	"errors"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

var publicNetwork *drawio.PublicNetworkTreeNode = nil
var externalTreeNodes = map[VPCResourceIntf]drawio.TreeNodeInterface{}

func (exn *ExternalNetwork) DrawioTreeNode(network drawio.TreeNodeInterface) drawio.TreeNodeInterface {
	if _, ok := externalTreeNodes[exn]; !ok {
		externalTreeNodes[exn] = drawio.NewInternetTreeNode(publicNetwork, exn.CidrStr)
	}
	return externalTreeNodes[exn]
}
func isExternal(i VPCResourceIntf) bool {
	_, ok := externalTreeNodes[i]
	return ok
}




type Edge struct {
	src   Node
	dst   Node
	label string
}

// DrawioOutputFormatter create the drawio connectivity map.
// It build the drawio tree out of the CloudConfig and VPCConnectivity, and output it to a drawio file
// the steps of creating the drawio tree:
// 1. collect all the connectivity edges to a map of (src,dst,label) -> isDirected. also mark the nodes that has connections
// 2. create the treeNodes of the squares out of the cConfig.NodeSets -  network, VPCs zones and subnets
// (also zones are created on demand from the zone names in the nodeSet details)
// 3. from the cConfig.filters,  create treeNodes of SGs, and give ACL to subnets
// 4. create the icons Tree nodes out of the cConfig.Nodes
// 5. create the VSIs tree nodes from cConfig.NodeSets
// 6. create the routers from cConfig.routers
// 7. create the edges from the map we created in stage (1). also also set the routers to the edges


type DrawioOutputFormatter struct {
	cConfig        *CloudConfig
	conn           *VPCConnectivity
	network        *drawio.NetworkTreeNode
	publicNetwork  *drawio.PublicNetworkTreeNode
	connectedNodes map[VPCResourceIntf]bool
	routers        map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface
	isEdgeDirected map[Edge]bool
}

func (d *DrawioOutputFormatter) init(cConfig *CloudConfig, conn *VPCConnectivity) {
	d.cConfig = cConfig
	d.conn = conn
	d.connectedNodes = map[VPCResourceIntf]bool{}
	d.routers = map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface{}
	d.isEdgeDirected = map[Edge]bool{}
}

func (d *DrawioOutputFormatter) WriteOutputAllEndpoints(cConfig *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (
	string, error) {
	d.init(cConfig, conn)
	d.createDrawioTree()
	err := drawio.CreateDrawioConnectivityMapFile(d.network, outFile)
	return "", err
}

func (d *DrawioOutputFormatter) createDrawioTree() {
	if d.conn != nil {
		d.createEdgesMap()
	}
	d.network = drawio.NewNetworkTreeNode()
	d.publicNetwork = drawio.NewPublicNetworkTreeNode(d.network)
	publicNetwork = d.publicNetwork

	d.createNodeSets()
	d.createNodes()
	d.createFilters()
	d.createRouters()
	d.createEdges()
}

func (d *DrawioOutputFormatter) createEdgesMap() {
	for src, srcMap := range d.conn.AllowedConnsCombined {
		for dst, conn := range srcMap {
			if conn.IsEmpty() {
				continue
			}
			label := conn.String()
			if conn.AllowAll {
				label = ""
			}
			edge := Edge{src, dst, label}
			revEdge := Edge{dst, src, label}
			_, revExist := d.isEdgeDirected[revEdge]
			if revExist {
				d.isEdgeDirected[revEdge] = false
			} else {
				d.isEdgeDirected[edge] = true
			}
			d.connectedNodes[src] = true
			d.connectedNodes[dst] = true
		}
	}
}

func (d *DrawioOutputFormatter) createNodeSets() {
	for _, ns := range d.cConfig.NodeSets {
		ns.DrawioTreeNode(d.network)
	}
}

func (d *DrawioOutputFormatter) createFilters() {
	for _, fl := range d.cConfig.FilterResources {
		fl.DrawioTreeNode(d.network)
	}
}

func (d *DrawioOutputFormatter) createNodes() {
	for _, n := range d.cConfig.Nodes {
		n.DrawioTreeNode(d.network)
	}
}

func (d *DrawioOutputFormatter) createRouters() {
	for _, r := range d.cConfig.RoutingResources {
		rTn := r.DrawioTreeNode(d.network)
		for _, ni := range r.Src() {
			d.routers[ni.DrawioTreeNode(d.network)] = rTn.(drawio.IconTreeNodeInterface)
		}
	}
}

func (d *DrawioOutputFormatter) createEdges() {
	for edge, directed := range d.isEdgeDirected {
		srcTn := edge.src.DrawioTreeNode(d.network).(drawio.IconTreeNodeInterface)
		dstTn := edge.dst.DrawioTreeNode(d.network).(drawio.IconTreeNodeInterface)
		cn := drawio.NewConnectivityLineTreeNode(d.network, srcTn, dstTn, directed, edge.label)
		if d.routers[srcTn] != nil && isExternal(edge.dst) {
			cn.SetRouter(d.routers[srcTn], false)
		}
		if d.routers[dstTn] != nil && isExternal(edge.src) {
			cn.SetRouter(d.routers[dstTn], true)
		}
	}
}

func (d *DrawioOutputFormatter) WriteOutputAllSubnets(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error) {
	return "", errors.New("SubnetLevel use case not supported for draw.io format currently ")
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
