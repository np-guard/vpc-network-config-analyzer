package vpcmodel

import (
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

const (
	commaSeparator = ","
)

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
	cConfig                  *CloudConfig
	conn                     *VPCConnectivity
	network                  *drawio.NetworkTreeNode
	vpc                      *drawio.VpcTreeNode
	zoneNameToZonesTreeNodes map[string]*drawio.ZoneTreeNode
	uidToSubnetsTreeNodes    map[string]*drawio.SubnetTreeNode
	cidrToSubnetsTreeNodes   map[string]*drawio.SubnetTreeNode
	allIconsTreeNodes        map[NamedResourceIntf]drawio.IconTreeNodeInterface
	isExternalIcon           map[drawio.IconTreeNodeInterface]bool
	connectedNodes           map[NamedResourceIntf]bool
	routers                  map[drawio.IconTreeNodeInterface]drawio.IconTreeNodeInterface
	sgMembers                map[string]*drawio.SGTreeNode
	isEdgeDirected           map[Edge]bool
}

func (d *DrawioOutputFormatter) init(cConfig *CloudConfig, conn *VPCConnectivity) {
	d.cConfig = cConfig
	d.conn = conn
	d.zoneNameToZonesTreeNodes = map[string]*drawio.ZoneTreeNode{}
	d.uidToSubnetsTreeNodes = map[string]*drawio.SubnetTreeNode{}
	d.cidrToSubnetsTreeNodes = map[string]*drawio.SubnetTreeNode{}
	d.allIconsTreeNodes = map[NamedResourceIntf]drawio.IconTreeNodeInterface{}
	d.isExternalIcon = map[drawio.IconTreeNodeInterface]bool{}
	d.connectedNodes = map[NamedResourceIntf]bool{}
	d.routers = map[drawio.IconTreeNodeInterface]drawio.IconTreeNodeInterface{}
	d.sgMembers = map[string]*drawio.SGTreeNode{}
	d.isEdgeDirected = map[Edge]bool{}
}

func (d *DrawioOutputFormatter) WriteOutput(cConfig *CloudConfig, conn *VPCConnectivity, outFile string) (string, error) {
	d.init(cConfig, conn)
	d.createDrawioTree()
	err := drawio.CreateDrawioConnectivityMapFile(d.network, outFile)
	return "", err
}

func (d *DrawioOutputFormatter) createDrawioTree() {
	d.createEdgesMap()
	d.createNodeSets()
	d.createFilters()
	d.createNodes()
	d.createVSIs()
	d.createRouters()
	d.createEdges()
}

func (d *DrawioOutputFormatter) getZoneTreeNode(resource NamedResourceIntf) *drawio.ZoneTreeNode {
	zoneName := resource.ZoneName()
	if _, ok := d.zoneNameToZonesTreeNodes[zoneName]; !ok {
		d.zoneNameToZonesTreeNodes[zoneName] = drawio.NewZoneTreeNode(d.vpc, zoneName)
	}
	return d.zoneNameToZonesTreeNodes[zoneName]
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
	d.network = drawio.NewNetworkTreeNode()
	// todo: support multi vnc
	for _, ns := range d.cConfig.NodeSets {
		details := ns.DetailsMap()
		if details[DetailsAttributeKind] == "VPC" {
			d.vpc = drawio.NewVpcTreeNode(d.network, details[DetailsAttributeName])
		}
	}
	for _, ns := range d.cConfig.NodeSets {
		details := ns.DetailsMap()
		if details[DetailsAttributeKind] == "Subnet" {
			subnet := drawio.NewSubnetTreeNode(d.getZoneTreeNode(ns), details[DetailsAttributeName], details["cidr"], "")
			d.uidToSubnetsTreeNodes[details["uid"]] = subnet
			d.cidrToSubnetsTreeNodes[details["cidr"]] = subnet
		}
	}
}

func (d *DrawioOutputFormatter) createFilters() {
	for _, fl := range d.cConfig.FilterResources {
		for _, details := range fl.DetailsMap() {
			if details[DetailsAttributeKind] == "SG" {
				sgTn := drawio.NewSGTreeNode(d.vpc, details["name"])
				for _, member := range strings.Split(details["members"], commaSeparator) {
					d.sgMembers[member] = sgTn
				}
			} else if details[DetailsAttributeKind] == "NACL" {
				for _, subnetCidr := range strings.Split(details["subnets"], commaSeparator) {
					if subnetCidr != "" {
						d.cidrToSubnetsTreeNodes[subnetCidr].SetACL(details["name"])
					}
				}
			}
		}
	}
}

func (d *DrawioOutputFormatter) createNodes() {
	for _, n := range d.cConfig.Nodes {
		details := n.DetailsMap()
		if details[DetailsAttributeKind] == "NetworkInterface" {
			// todo: what is the name of NI
			d.allIconsTreeNodes[n] = drawio.NewNITreeNode(
				d.uidToSubnetsTreeNodes[details["subnetUID"]],
				d.sgMembers[details["address"]], details["name"])
		} else if details[DetailsAttributeKind] == externalNetworkNodeKind {
			if d.connectedNodes[n] {
				d.allIconsTreeNodes[n] = drawio.NewInternetTreeNode(d.network, details[DetailsAttributeCIDR])
				d.isExternalIcon[d.allIconsTreeNodes[n]] = true
			}
		}
	}
}

func (d *DrawioOutputFormatter) createVSIs() {
	for _, ns := range d.cConfig.NodeSets {
		details := ns.DetailsMap()
		if details[DetailsAttributeKind] == "VSI" {
			if len(ns.Nodes()) == 0 {
				continue
			} else {
				vsiNIs := []drawio.TreeNodeInterface{}
				for _, ni := range ns.Nodes() {
					vsiNIs = append(vsiNIs, d.allIconsTreeNodes[ni])
				}
				drawio.GroupNIsWithVSI(d.getZoneTreeNode(ns), ns.Name(), vsiNIs)
			}
		}
	}
}

func (d *DrawioOutputFormatter) createRouters() {
	for _, r := range d.cConfig.RoutingResources {
		dm := r.DetailsMap()
		if dm[DetailsAttributeKind] == "PublicGateway" {
			pgwTn := drawio.NewGatewayTreeNode(d.getZoneTreeNode(r), dm[DetailsAttributeName])
			d.allIconsTreeNodes[r] = pgwTn
			for _, ni := range r.Src() {
				d.routers[d.allIconsTreeNodes[ni]] = pgwTn
			}
		}
		if dm[DetailsAttributeKind] == "FloatingIP" {
			// todo - what if r.Src() is not at size of one?
			nitn := d.allIconsTreeNodes[r.Src()[0]].(*drawio.NITreeNode)
			nitn.SetFIP(r.Name())
			d.routers[nitn] = nitn
		}
	}
}

func (d *DrawioOutputFormatter) createEdges() {
	for edge, directed := range d.isEdgeDirected {
		srcTn := d.allIconsTreeNodes[edge.src]
		dstTn := d.allIconsTreeNodes[edge.dst]
		cn := drawio.NewConnectivityLineTreeNode(d.network, srcTn, dstTn, directed, edge.label)
		if d.routers[srcTn] != nil && d.isExternalIcon[dstTn] {
			cn.SetRouter(d.routers[srcTn], false)
		}
		if d.routers[dstTn] != nil && d.isExternalIcon[srcTn] {
			cn.SetRouter(d.routers[dstTn], true)
		}
	}
}
