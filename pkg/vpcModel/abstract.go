package vpcmodel

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

///////////////////////////vpc resources////////////////////////////////////////////////////////////////////////////
//define DS as input level resources + their semantics

//define DS for connectivity map

//define output - as processing of connectivity map

// network interface , reserved ip, external cidrs
type Node interface {
	Name() string
	Cidr() string
	IsInternal() bool
}

//vpc ,subnet, vsi, service network
type NodeSet interface {
	Name() string
	Nodes() []Node
	Connectivity() *ConnectivityResult
}

type FilterTrafficRule interface {
	Src() string
	Dst() string
	Action() string
	Connections() string
}

//capture allowed traffic between 2 endpoints
type FilterTraffic interface {
	InboundRules() []FilterTrafficRule
	OutboundRules() []FilterTrafficRule
	// get the connectivity result when the filterTraffic resource is applied to the given NodeSet element
	Connectivity(nodes NodeSet) *ConnectivityResult
	//AllowedConnectivity(src, dst Node) *common.ConnectionSet
}

// given a filterTraffic resource, check if the input traffic is allowed and by which connections
func AllowedConnectivity(f FilterTraffic, src, dst Node, isIngress bool) *common.ConnectionSet {
	// TODO: implement
	return allConns()
}

//routing resource enables connectivity from src to destination via that resource
//fip, pgw, vpe
type RoutingResource interface {
	Name() string
	Src() []Node
	Destinations() []Node
}

//////////////////////////////////////////////////////////////////////////////////////////////
// connectivity model aspects

type ConnectivityResult struct {
	IngressAllowedConns map[Node]*common.ConnectionSet
	EgressAllowedConns  map[Node]*common.ConnectionSet
}

type VPCConfig struct {
	Nodes           []Node
	NodeSets        []NodeSet
	FilterResources []FilterTraffic
}

//detailed representation of allowed connectivity considering all resources in a vpc config instance
type VPCConnectivity struct {
	// computed for each node, by iterating its ConnectivityResult for all relevant VPC resources that capture it
	AllowedConns map[Node]*ConnectivityResult
	// combined connectivity - considering both ingress and egress per connection
	AllowedConnsCombined map[Node]map[Node]*ConnectivityResult
}

// a processing of VPCConnectivity produces ConnectivityOutput, at various formats
type ConnectivityOutput struct {
}

func (v *VPCConnectivity) String() string {
	res := ""
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
	return res
}

func allConns() *common.ConnectionSet {
	res := common.MakeConnectionSet(true)
	return &res
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
			allowedConnsBetweenCapturedAndPeerNode := allConns()
			for _, filter := range v.FilterResources {
				filteredConns := AllowedConnectivity(filter, src, dst, isIngress)
				allowedConnsBetweenCapturedAndPeerNode.Intersection(*filteredConns)
				if allowedConnsBetweenCapturedAndPeerNode.IsEmpty() {
					break
				}
			}
			// else : external node -> consider attached routing resources
			//...
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
