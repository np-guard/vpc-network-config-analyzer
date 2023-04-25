package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// define DS as input level resources + their semantics

// define DS for connectivity map

// define output - as processing of connectivity map

///////////////////////////vpc resources////////////////////////////////////////////////////////////////////////////

// Node is the basic endpoint element in the connectivity graph [ network interface , reserved ip, external cidrs]
type NamedResourceIntf interface {
	UID() string
	Name() string
}

type Node interface {
	NamedResourceIntf
	Cidr() string
	IsInternal() bool
	Details() string
	DetailsMap() map[string]string
}

// NodeSet is an element that may capture several nodes [vpc ,subnet, vsi, (service network?)]
type NodeSet interface {
	NamedResourceIntf
	Nodes() []Node
	Connectivity() *ConnectivityResult
	Details() string
	DetailsMap() map[string]string
}

// FilterTrafficResource capture allowed traffic between 2 endpoints
type FilterTrafficResource interface {
	NamedResourceIntf
	// get the connectivity result when the filterTraffic resource is applied to the given NodeSet element
	AllowedConnectivity(src, dst Node, isIngress bool) *common.ConnectionSet
	Kind() string
	ReferencedIPblocks() []*common.IPBlock
	Details() []string
	DetailsMap() []map[string]string
}

// routing resource enables connectivity from src to destination via that resource
// fip, pgw, vpe
type RoutingResource interface {
	NamedResourceIntf
	Src() []Node
	Destinations() []Node
	AllowedConnectivity(src, dst Node) *common.ConnectionSet
	Details() string
	DetailsMap() map[string]string
}

//////////////////////////////////////////////////////////////////////////////////////////////

type NamedResource struct {
	ResourceName string
	ResourceUID  string
}

func (n *NamedResource) Name() string {
	return n.ResourceName
}

func (n *NamedResource) UID() string {
	return n.ResourceUID
}

//////////////////////////////////////////////////////////////////////////////////////////////

const (
	DetailsAttributeKind = "kind"
	DetailsAttributeName = "name"
	DetailsAttributeCIDR = "cidr"
)

type ExternalNetwork struct {
	NamedResource
	CidrStr string
}

func (exn *ExternalNetwork) Cidr() string {
	return exn.CidrStr
}

func (exn *ExternalNetwork) Name() string {
	return exn.CidrStr
}

func (exn *ExternalNetwork) IsInternal() bool {
	return false
}

func (exn *ExternalNetwork) Details() string {
	return "ExternalNetwork " + exn.Cidr()
}

func (exn *ExternalNetwork) Kind() string {
	return "ExternalNetwork"
}

func (exn *ExternalNetwork) DetailsMap() map[string]string {
	res := map[string]string{}
	res[DetailsAttributeKind] = exn.Kind()
	res[DetailsAttributeName] = exn.ResourceName
	res[DetailsAttributeCIDR] = exn.CidrStr
	return res
}

//////////////////////////////////////////////////////////////////////////////////////////////

// connectivity model aspects

type ConnectivityResult struct {
	IngressAllowedConns map[Node]*common.ConnectionSet
	EgressAllowedConns  map[Node]*common.ConnectionSet
}

type CloudConfig struct {
	Nodes            []Node
	NodeSets         []NodeSet
	FilterResources  []FilterTrafficResource
	RoutingResources []RoutingResource
}

func addDetailsLine(lines []string, details string) []string {
	if details != "" {
		lines = append(lines, details)
	}
	return lines
}

func (v *CloudConfig) String() string {
	res := "cloud config details:\n"
	lines := []string{}
	for _, node := range v.Nodes {
		lines = addDetailsLine(lines, node.Details())
	}
	for _, nodeSet := range v.NodeSets {
		lines = addDetailsLine(lines, nodeSet.Details())
	}
	for _, filters := range v.FilterResources {
		lines = append(lines, filters.Details()...)
	}
	for _, r := range v.RoutingResources {
		lines = addDetailsLine(lines, r.Details())
	}
	res += strings.Join(lines, "\n")
	return res
}

// detailed representation of allowed connectivity considering all resources in a vpc config instance
type VPCConnectivity struct {
	// computed for each node, by iterating its ConnectivityResult for all relevant VPC resources that capture it
	AllowedConns map[Node]*ConnectivityResult
	// combined connectivity - considering both ingress and egress per connection
	AllowedConnsCombined map[Node]map[Node]*common.ConnectionSet
}

// a processing of VPCConnectivity produces ConnectivityOutput, at various formats
type ConnectivityOutput struct {
}

// add interface to output formatter

func getConnectionStr(src, dst, conn, suffix string) string {
	return fmt.Sprintf("%s => %s : %s%s\n", src, dst, conn, suffix)
}

func (v *VPCConnectivity) String() string {
	res := "=================================== distributed inbound/outbound connections:\n"
	strList := []string{}
	for node, connectivity := range v.AllowedConns {
		// ingress
		for peerNode, conn := range connectivity.IngressAllowedConns {
			strList = append(strList, getConnectionStr(peerNode.Cidr(), node.Cidr(), conn.String(), " [inbound]"))
		}
		// egress
		for peerNode, conn := range connectivity.EgressAllowedConns {
			strList = append(strList, getConnectionStr(node.Cidr(), peerNode.Cidr(), conn.String(), " [outbound]"))
		}
	}
	sort.Strings(strList)
	res += strings.Join(strList, "")
	res += "=================================== combined connections:\n"
	strList = []string{}
	for src, nodeConns := range v.AllowedConnsCombined {
		for dst, conns := range nodeConns {
			strList = append(strList, getConnectionStr(src.Cidr(), dst.Cidr(), conns.String(), ""))
		}
	}
	sort.Strings(strList)
	res += strings.Join(strList, "")
	res += "=================================== combined connections - short version:\n"
	strList = []string{}
	for src, nodeConns := range v.AllowedConnsCombined {
		for dst, conns := range nodeConns {
			if conns.IsEmpty() {
				continue
			}
			srcName := src.Cidr()
			if src.IsInternal() {
				srcName = src.Name()
			}
			dstName := dst.Cidr()
			if dst.IsInternal() {
				dstName = dst.Name()
			}
			strList = append(strList, getConnectionStr(srcName, dstName, conns.String(), ""))
		}
	}
	sort.Strings(strList)
	res += strings.Join(strList, "")
	return res
}

func (v *CloudConfig) GetVPCNetworkConnectivity() *VPCConnectivity {
	res := &VPCConnectivity{AllowedConns: map[Node]*ConnectivityResult{}}
	// get connectivity in level of nodes elements
	for _, node := range v.Nodes {
		if node.IsInternal() {
			res.AllowedConns[node] = &ConnectivityResult{
				IngressAllowedConns: v.getAllowedConnsPerDirection(true, node),
				EgressAllowedConns:  v.getAllowedConnsPerDirection(false, node),
			}
		}
	}
	res.computeAllowedConnsCombined()
	return res
}

func (v *VPCConnectivity) computeAllowedConnsCombined() {
	v.AllowedConnsCombined = map[Node]map[Node]*common.ConnectionSet{}

	for node, connectivityRes := range v.AllowedConns {
		for peerNode, conns := range connectivityRes.IngressAllowedConns {
			src := peerNode
			dst := node
			combinedConns := conns
			if peerNode.IsInternal() {
				egressConns := v.AllowedConns[peerNode].EgressAllowedConns[node]
				combinedConns.Intersection(*egressConns)
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[Node]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
		for peerNode, conns := range connectivityRes.EgressAllowedConns {
			src := node
			dst := peerNode
			combinedConns := conns
			if peerNode.IsInternal() {
				ingressConss := v.AllowedConns[peerNode].IngressAllowedConns[node]
				combinedConns.Intersection(*ingressConss)
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[Node]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
	}
}

func AllConns() *common.ConnectionSet {
	res := common.MakeConnectionSet(true)
	return &res
}

func NoConns() *common.ConnectionSet {
	res := common.MakeConnectionSet(false)
	return &res
}

func HasNode(listNodes []Node, node Node) bool {
	for _, n := range listNodes {
		if n.Cidr() == node.Cidr() {
			return true
		}
	}
	return false
}

func (v *CloudConfig) getAllowedConnsPerDirection(isIngress bool, capturedNode Node) map[Node]*common.ConnectionSet {
	res := map[Node]*common.ConnectionSet{}
	var src, dst Node
	for _, peerNode := range v.Nodes {
		if peerNode.Cidr() == capturedNode.Cidr() {
			continue
		}
		if isIngress {
			src = peerNode
			dst = capturedNode
		} else {
			src = capturedNode
			dst = peerNode
		}
		if peerNode.IsInternal() {
			// no need for router node, connectivity is from within VPC
			// only check filtering resources
			allowedConnsBetweenCapturedAndPeerNode := AllConns()
			for _, filter := range v.FilterResources {
				// TODO: cannot do intersection per all sg resources - connectivity is additive in sg layer .
				// only intersection between layers - sg vs nacl
				// each layer of filter resources should have its own logic
				// consider accumulate all filter resources of the same type, and send to a function that returns combined result.
				filteredConns := filter.AllowedConnectivity(src, dst, isIngress)
				allowedConnsBetweenCapturedAndPeerNode.Intersection(*filteredConns)
				if allowedConnsBetweenCapturedAndPeerNode.IsEmpty() {
					break
				}
			}
			res[peerNode] = allowedConnsBetweenCapturedAndPeerNode
			direction := "inbound"
			if !isIngress {
				direction = "outbound"
			}
			fmt.Printf("getAllowedConnsPerDirection: src: %s, dst %s, conn: %s, direction: %s\n", src.Cidr(), dst.Cidr(),
				allowedConnsBetweenCapturedAndPeerNode.String(), direction)
		} else { // else : external node -> consider attached routing resources
			allowedConnsBetweenCapturedAndPeerNode := NoConns()
			for _, router := range v.RoutingResources {
				routerConnRes := router.AllowedConnectivity(src, dst)
				if !routerConnRes.IsEmpty() { // connection is allowed through router resource
					// TODO: consider adding connection attribute with details of routing through this router resource
					allowedConnsBetweenCapturedAndPeerNode = routerConnRes
				}
			}
			for _, filter := range v.FilterResources {
				filteredConns := filter.AllowedConnectivity(src, dst, isIngress)
				allowedConnsBetweenCapturedAndPeerNode.Intersection(*filteredConns)
				if allowedConnsBetweenCapturedAndPeerNode.IsEmpty() {
					break
				}
			}
			res[peerNode] = allowedConnsBetweenCapturedAndPeerNode
		}
	}
	return res
}

/////////////////////////////////////////////////////////////////////////////////
/*type Vpc interface {
	Name() string
	Cidr() string
	Region() string
}

//Zone and regions are properties of nodes
type Zone interface {
	Name() string
	Cidr() string
	//VPC() Vpc
}

type Instance interface {
	Name() string
	Zone() Zone
	//Subnet() Subnet
	NetworkInterfaces() []NetworkInterface
}

type Subnet interface {
	Name() string
	Cidr() string
	Zone() Zone
}

type FilterTrafficResource interface {
	Name() string
	Captures() []NetworkInterface
	//connectivity rules
	// connectivity result
}

type GatewayResource interface {
	Captures() []NetworkInterface
	//connectivity rules
	// connectivity result

}

type RoutingResource interface {
	Name() string
}

//LB?

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

//endpoints: Instance (NetworkInterface list) , ReservedIPs , private external cidr, public internet cidr

type Peer interface {
	Name() string
}

type NetworkInterface interface {
	Name() string
	Address() string
	Subnet() Subnet
}

type External interface {
	Name() string
	Cidr() string
	IsPublic() bool
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////vpc connectivity ////////////////////////////////////////////////////////

type Connection interface {
	ConnAttributes() string
}

type PeerPairs interface {
	Name() string
	Src() Peer
	Dst() Peer
}

type ConnectionMap interface {
	Output() string
	ConnectionsMap() map[PeerPairs]Connection
}*/

/*
resource types:
vpcNode
externalNode
filterTrafficResource
gwResource

// connectivity view: with/without mid-nodes (e.g gw resources)



// connectivity facts:
Subnets within the VPC offer private connectivity; they can talk to each other over a private link through
 the implicit router. Setting up routes is not necessary.
vsis in the same vpc are connected
only pub-gw and floating-ip has connectivity to internet [they should be removed from output in simplified connectivity map]


Subnets in your VPC can connect to the public internet through an optional public gateway.
You can assign floating IP addresses to any virtual server instance to enable it to be reachable from the internet,
 independent of whether its subnet is attached to a public gateway.

//Each VPC is deployed to a single region. Within that region, the VPC can span multiple zones.


A region is an abstraction that is related to the geographic area in which a VPC is deployed.
Each region contains multiple zones, which represent independent fault domains.
A VPC can span multiple zones within its assigned region.

*/
