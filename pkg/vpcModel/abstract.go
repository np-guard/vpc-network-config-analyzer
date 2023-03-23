package vpcmodel

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

//define DS as input level resources + their semantics

//define DS for connectivity map

//define output - as processing of connectivity map

///////////////////////////vpc resources////////////////////////////////////////////////////////////////////////////

// Node is the basic endpoint element in the connectivity graph [ network interface , reserved ip, external cidrs]
type NamedResource interface {
	Name() string
}

type Node interface {
	NamedResource
	Cidr() string
	IsInternal() bool
}

// NodeSet is an element that may capture several nodes [vpc ,subnet, vsi, (service network?)]
type NodeSet interface {
	NamedResource
	Nodes() []Node
	Connectivity() *ConnectivityResult
}

// rename to FilterTrafficResource
// FilterTraffic capture allowed traffic between 2 endpoints
type FilterTraffic interface {
	NamedResource
	InboundRules() []FilterTrafficRule
	OutboundRules() []FilterTrafficRule
	// get the connectivity result when the filterTraffic resource is applied to the given NodeSet element
	Connectivity(nodes NodeSet) *ConnectivityResult
	AllowedConnectivity(src, dst Node, isIngress bool) *common.ConnectionSet
}

type FilterTrafficRule interface {
	Src() string
	Dst() string
	Action() string
	Connections() string
}

//routing resource enables connectivity from src to destination via that resource
//fip, pgw, vpe
type RoutingResource interface {
	NamedResource
	Src() []Node
	Destinations() []Node
	AllowedConnectivity(src, dst Node) *common.ConnectionSet
}

//////////////////////////////////////////////////////////////////////////////////////////////
// connectivity model aspects

type ConnectivityResult struct {
	IngressAllowedConns map[Node]*common.ConnectionSet
	EgressAllowedConns  map[Node]*common.ConnectionSet
}

type VPCConfig struct {
	Nodes            []Node
	NodeSets         []NodeSet
	FilterResources  []FilterTraffic
	RoutingResources []RoutingResource
}

//detailed representation of allowed connectivity considering all resources in a vpc config instance
type VPCConnectivity struct {
	// computed for each node, by iterating its ConnectivityResult for all relevant VPC resources that capture it
	AllowedConns map[Node]*ConnectivityResult
	// combined connectivity - considering both ingress and egress per connection
	AllowedConnsCombined map[Node]map[Node]*common.ConnectionSet
}

// a processing of VPCConnectivity produces ConnectivityOutput, at various formats
type ConnectivityOutput struct {
}

//add interface to output formatter

func (v *VPCConnectivity) String() string {
	res := "=================================== distributed inbound/outbound connections:\n"
	for node, connectivity := range v.AllowedConns {
		// ingress
		for peerNode, conn := range connectivity.IngressAllowedConns {
			res += fmt.Sprintf("%s => %s : %s [inbound]\n", peerNode.Cidr(), node.Cidr(), conn.String())
		}
		// egress
		for peerNode, conn := range connectivity.EgressAllowedConns {
			res += fmt.Sprintf("%s => %s : %s [outbound]\n", node.Cidr(), peerNode.Cidr(), conn.String())
		}
	}
	res += "=================================== combined connections:\n"
	for src, nodeConns := range v.AllowedConnsCombined {
		for dst, conns := range nodeConns {
			res += fmt.Sprintf("%s => %s : %s\n", src.Cidr(), dst.Cidr(), conns.String())
		}
	}

	return res
}

func (v *VPCConfig) GetVPCNetworkConnectivity() *VPCConnectivity {
	res := &VPCConnectivity{AllowedConns: map[Node]*ConnectivityResult{}}
	// get connectivity in level of nodes elements
	for _, node := range v.Nodes {
		if node.IsInternal() { //if _, ok := node.(*NetworkInterface); ok {
			res.AllowedConns[node] = &ConnectivityResult{
				IngressAllowedConns: v.getAllowedConnsPerDirection(true, node),  //map[Node]*common.ConnectionSet{},
				EgressAllowedConns:  v.getAllowedConnsPerDirection(false, node), //map[Node]*common.ConnectionSet{},
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

func (v *VPCConfig) getAllowedConnsPerDirection(isIngress bool, capturedNode Node) map[Node]*common.ConnectionSet {
	res := map[Node]*common.ConnectionSet{}
	var src, dst Node
	for _, peerNode := range v.Nodes {
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
				filteredConns := filter.AllowedConnectivity(src, dst, isIngress)
				allowedConnsBetweenCapturedAndPeerNode.Intersection(*filteredConns)
				if allowedConnsBetweenCapturedAndPeerNode.IsEmpty() {
					break
				}
			}
			res[peerNode] = allowedConnsBetweenCapturedAndPeerNode
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
Subnets within the VPC offer private connectivity; they can talk to each other over a private link through the implicit router. Setting up routes is not necessary.
vsis in the same vpc are connected
only pub-gw and floating-ip has connectivity to internet [they should be removed from output in simplified connectivity map]


Subnets in your VPC can connect to the public internet through an optional public gateway.
You can assign floating IP addresses to any virtual server instance to enable it to be reachable from the internet, independent of whether its subnet is attached to a public gateway.

//Each VPC is deployed to a single region. Within that region, the VPC can span multiple zones.


A region is an abstraction that is related to the geographic area in which a VPC is deployed.
Each region contains multiple zones, which represent independent fault domains.
A VPC can span multiple zones within its assigned region.

*/
