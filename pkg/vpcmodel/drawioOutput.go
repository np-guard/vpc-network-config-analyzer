package vpcmodel

import (
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

type Edge struct {
	src   Node
	dst   Node
	label string
}

type DrawioOutputFormatter struct {
	network             *drawio.NetworkTreeNode
	vpc                 *drawio.VpcTreeNode
	allZonesTreeNodes   map[string]*drawio.ZoneTreeNode
	allSubnetsTreeNodes map[string]*drawio.SubnetTreeNode
	allIconsTreeNodes   map[interface{}]drawio.IconTreeNodeInterface
	ConnectedNodes      map[interface{}]bool
	routers             map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface
	sgMembers           map[string]*drawio.SGTreeNode
	isEdgeDirected      map[Edge]bool
}

func (d *DrawioOutputFormatter) init() {
	d.allZonesTreeNodes = map[string]*drawio.ZoneTreeNode{}
	d.allSubnetsTreeNodes = map[string]*drawio.SubnetTreeNode{}
	d.allIconsTreeNodes = map[interface{}]drawio.IconTreeNodeInterface{}
	d.ConnectedNodes = map[interface{}]bool{}
	d.routers = map[drawio.TreeNodeInterface]drawio.IconTreeNodeInterface{}
	d.sgMembers = map[string]*drawio.SGTreeNode{}
	d.isEdgeDirected = map[Edge]bool{}
}

func (d *DrawioOutputFormatter) WriteOutput(c *CloudConfig, conn *VPCConnectivity, outFile string) (string, error) {
	d.init()
	network := d.createNetwork(c, conn)
	drawio.CreateDrawioConnectivityMapFile(network, outFile)
	return "", nil
}

func (d *DrawioOutputFormatter) createNetwork(c *CloudConfig, conn *VPCConnectivity) drawio.SquareTreeNodeInterface {
	d.createEdgesMap(conn)
	d.createNodeSets(c)
	d.createFilters(c)
	d.createNodes(c)
	d.createRouters(c)
	d.createEdges()
	return d.network
}

func (d *DrawioOutputFormatter) getZoneTN(a NamedResourceIntf) *drawio.ZoneTreeNode {
	zoneName := a.(ZonalNamedResourceIntf).ZoneName()
	if _, ok := d.allZonesTreeNodes[zoneName]; !ok {
		d.allZonesTreeNodes[zoneName] = drawio.NewZoneTreeNode(d.vpc, zoneName)
	}
	return d.allZonesTreeNodes[zoneName]
}
func (d *DrawioOutputFormatter) createEdgesMap(conn *VPCConnectivity) {
	for src, srcMap := range conn.AllowedConnsCombined {
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
			d.ConnectedNodes[src] = true
			d.ConnectedNodes[dst] = true
		}
	}
}

func (d *DrawioOutputFormatter) createRouters(c *CloudConfig) {
	for _, r := range c.RoutingResources {
		dm := r.DetailsMap()
		if dm[DetailsAttributeKind] == "PublicGateway" {
			pgwTn := drawio.NewGatewayTreeNode(d.getZoneTN(r), dm[DetailsAttributeName])
			d.allIconsTreeNodes[r] = pgwTn
			for _, ni := range r.Src() {
				nitn := d.allIconsTreeNodes[ni].(*drawio.NITreeNode)
				d.routers[nitn] = pgwTn
			}
		}
		if dm[DetailsAttributeKind] == "FloatingIP" {
			nitn := d.allIconsTreeNodes[r.Src()[0]].(*drawio.NITreeNode)
			nitn.SetFIP(r.Name())
			d.routers[nitn] = nitn
		}
	}
}

func (d *DrawioOutputFormatter) createEdges() {
	for e, directed := range d.isEdgeDirected {
		srcTn := d.allIconsTreeNodes[e.src]
		dstTn := d.allIconsTreeNodes[e.dst]
		cn := drawio.NewConnectivityLineTreeNode(d.network, srcTn, dstTn, directed, e.label)
		// todo - can we get this info from the VPCConnectivity:
		if d.routers[srcTn] != nil && dstTn.IsInternet() {
			cn.SetRouter(d.routers[srcTn], false)
		}
		if d.routers[dstTn] != nil && srcTn.IsInternet() {
			cn.SetRouter(d.routers[dstTn], true)
		}
	}
}

func (d *DrawioOutputFormatter) createFilters(c *CloudConfig) {
	for _, fl := range c.FilterResources {
		dms := fl.DetailsMap()
		if fl.Kind() == "SecurityGroupLayer" {
			for _, dm := range dms {
				if dm[DetailsAttributeKind] == "SG" {
					sgTn := drawio.NewSGTreeNode(d.vpc, dm["name"])
					for _, member := range strings.Split(dm["members"], ",") {
						d.sgMembers[member] = sgTn
					}
				}
			}
		}
	}
}
func (d *DrawioOutputFormatter) createNodes(c *CloudConfig) {
	for _, n := range c.Nodes {
		dm := n.DetailsMap()
		if dm[DetailsAttributeKind] == "NetworkInterface" {
			d.allIconsTreeNodes[n] = drawio.NewNITreeNode(d.allSubnetsTreeNodes[dm["subnetUID"]], d.sgMembers[dm["address"]], "")
		} else if dm[DetailsAttributeKind] == "ExternalNetwork" {
			if d.ConnectedNodes[n] {
				d.allIconsTreeNodes[n] = drawio.NewInternetTreeNode(d.network, dm[DetailsAttributeCIDR])
			}
		}
	}
	for _, ns := range c.NodeSets {
		dm := ns.DetailsMap()
		if dm[DetailsAttributeKind] == "VSI" {
			if len(ns.Nodes()) == 0 {
				continue
			} else {
				vsiNIs := []drawio.TreeNodeInterface{}
				for _, ni := range ns.Nodes() {
					vsiNIs = append(vsiNIs, d.allIconsTreeNodes[ni])
				}
				drawio.GroupNIsWithVSI(d.getZoneTN(ns), ns.Name(), vsiNIs)
			}
		}
	}
}

func (d *DrawioOutputFormatter) createNodeSets(c *CloudConfig) {
	d.network = drawio.NewNetworkTreeNode()
	// todo: support multi vnc
	for _, ns := range c.NodeSets {
		dm := ns.DetailsMap()
		if dm[DetailsAttributeKind] == "VPC" {
			d.vpc = drawio.NewVpcTreeNode(d.network, dm[DetailsAttributeName])
		}
	}
	for _, ns := range c.NodeSets {
		dm := ns.DetailsMap()
		if dm[DetailsAttributeKind] == "Subnet" {
			d.allSubnetsTreeNodes[dm["uid"]] = drawio.NewSubnetTreeNode(d.getZoneTN(ns), dm[DetailsAttributeName], "ip", "key")
		}
	}

}
