package vpcmodel

import (
	"errors"
	"reflect"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/drawio"
)

const (
	commaSeparator = ","
	cidrAttr       = "cidr"
	nameAttr       = "name"
	nwInterface    = "NetworkInterface"
)

type edgeInfo struct {
	src   EndpointElem
	dst   EndpointElem
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
	publicNetwork            *drawio.PublicNetworkTreeNode
	vpc                      *drawio.VpcTreeNode
	zoneNameToZonesTreeNodes map[string]*drawio.ZoneTreeNode
	uidToSubnetsTreeNodes    map[string]*drawio.SubnetTreeNode
	cidrToSubnetsTreeNodes   map[string]*drawio.SubnetTreeNode
	allIconsTreeNodes        map[interface{}]drawio.IconTreeNodeInterface
	routers                  map[drawio.IconTreeNodeInterface]drawio.IconTreeNodeInterface
	sgMembers                map[string]*drawio.SGTreeNode
	isEdgeDirected           map[edgeInfo]bool
	publicNodesGroups        map[EndpointElem]bool
}

func (d *DrawioOutputFormatter) init(cConfig *CloudConfig, conn *VPCConnectivity) {
	d.cConfig = cConfig
	d.conn = conn
	d.zoneNameToZonesTreeNodes = map[string]*drawio.ZoneTreeNode{}
	d.uidToSubnetsTreeNodes = map[string]*drawio.SubnetTreeNode{}
	d.cidrToSubnetsTreeNodes = map[string]*drawio.SubnetTreeNode{}
	d.allIconsTreeNodes = map[interface{}]drawio.IconTreeNodeInterface{}
	d.routers = map[drawio.IconTreeNodeInterface]drawio.IconTreeNodeInterface{}
	d.sgMembers = map[string]*drawio.SGTreeNode{}
	d.isEdgeDirected = map[edgeInfo]bool{}
	d.publicNodesGroups = map[EndpointElem]bool{}

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
	d.createNodeSets()
	d.createFilters()
	d.createNodes()
	d.createVSIs()
	d.createRouters()
	d.createEdges()
}

func (d *DrawioOutputFormatter) getZoneTreeNode(resource VPCResourceIntf) *drawio.ZoneTreeNode {
	zoneName := resource.ZoneName()
	if _, ok := d.zoneNameToZonesTreeNodes[zoneName]; !ok {
		d.zoneNameToZonesTreeNodes[zoneName] = drawio.NewZoneTreeNode(d.vpc, zoneName)
	}
	return d.zoneNameToZonesTreeNodes[zoneName]
}

func (d *DrawioOutputFormatter) createEdgesMap() {
	for _, line := range d.conn.GroupedConnectivity.GroupedLines {
		src := line.Src
		dst := line.Dst
		label := line.Conn
		//todo - fix:
		if label == "All Connection"{
			label = ""
		}
		for _, ep := range []EndpointElem{src, dst} {
			switch reflect.TypeOf(ep).Elem() {
			case reflect.TypeOf(groupedExternalNodes{}):
				d.publicNodesGroups[ep] = true
			case reflect.TypeOf(groupedNetworkInterfaces{}):
				// todo: how to support this?
			default:
				// todo: what do we support? , how?

			}
		}
		//todo - simplify label
		edge := edgeInfo{src, dst, label}
		revEdge := edgeInfo{dst, src, label}
		_, revExist := d.isEdgeDirected[revEdge]
		if revExist {
			d.isEdgeDirected[revEdge] = false
		} else {
			d.isEdgeDirected[edge] = true
		}
	}
}

func (d *DrawioOutputFormatter) createNodeSets() {
	d.network = drawio.NewNetworkTreeNode()
	ibmCloud := drawio.NewCloudTreeNode(d.network, "IBM Cloud")
	d.publicNetwork = drawio.NewPublicNetworkTreeNode(d.network)
	// todo: support multi vnc
	for _, ns := range d.cConfig.NodeSets {
		details := ns.DetailsMap()[0]
		if details[DetailsAttributeKind] == "VPC" {
			d.vpc = drawio.NewVpcTreeNode(ibmCloud, details[DetailsAttributeName])
		}
	}
	for _, ns := range d.cConfig.NodeSets {
		details := ns.DetailsMap()[0]
		if details[DetailsAttributeKind] == subnetKind {
			subnet := drawio.NewSubnetTreeNode(d.getZoneTreeNode(ns), details[DetailsAttributeName], details[cidrAttr], "")
			d.uidToSubnetsTreeNodes[details["uid"]] = subnet
			d.cidrToSubnetsTreeNodes[details[cidrAttr]] = subnet
		}
	}
}

func (d *DrawioOutputFormatter) createFilters() {
	for _, fl := range d.cConfig.FilterResources {
		for _, details := range fl.DetailsMap() {
			if details[DetailsAttributeKind] == "SG" {
				sgTn := drawio.NewSGTreeNode(d.vpc, details[nameAttr])
				for _, member := range strings.Split(details["members"], commaSeparator) {
					d.sgMembers[member] = sgTn
				}
			} else if details[DetailsAttributeKind] == "NACL" {
				for _, subnetCidr := range strings.Split(details["subnets"], commaSeparator) {
					if subnetCidr != "" {
						d.cidrToSubnetsTreeNodes[subnetCidr].SetACL(details[nameAttr])
					}
				}
			}
		}
	}
}

func (d *DrawioOutputFormatter) createNodes() {
	for _, n := range d.cConfig.Nodes {
		details := n.DetailsMap()[0]
		if details[DetailsAttributeKind] == nwInterface {
			// todo: what is the name of NI
			d.allIconsTreeNodes[n] = drawio.NewNITreeNode(
				d.uidToSubnetsTreeNodes[details["subnetUID"]],
				d.sgMembers[details["address"]], details[nameAttr])
		}
	}
	for pg := range d.publicNodesGroups {
		// todo -  simplify name, if it is long:
		d.allIconsTreeNodes[pg] = drawio.NewInternetTreeNode(d.publicNetwork, pg.Name())
		nodes := pg.(*groupedExternalNodes)
		if len(*nodes) > 1{
			tooltip := []string{}
			for _, n :=	range *nodes{
				tooltip = append(tooltip, n.Cidr())
			}
			d.allIconsTreeNodes[pg].SetTooltip(tooltip)
		}
	}
}

func (d *DrawioOutputFormatter) createVSIs() {
	for _, ns := range d.cConfig.NodeSets {
		details := ns.DetailsMap()[0]
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
		dm := r.DetailsMap()[0]
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
		if d.routers[srcTn] != nil && d.publicNodesGroups[edge.dst] {
			cn.SetRouter(d.routers[srcTn], false)
		}
		if d.routers[dstTn] != nil && d.publicNodesGroups[edge.src] {
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
