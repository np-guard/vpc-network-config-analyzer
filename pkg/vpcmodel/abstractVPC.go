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
	IsPublicInternet() bool
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
	// computed for each layer separately its allowed connections (ingress and egress separately)
	AllowedConnsPerLayer map[Node]map[string]*ConnectivityResult
	// computed for each node, by iterating its ConnectivityResult for all relevant VPC resources that capture it
	AllowedConns map[Node]*ConnectivityResult

	// combined connectivity - considering both ingress and egress per connection
	AllowedConnsCombined map[Node]map[Node]*common.ConnectionSet

	// allowed connectivity combined and stateful
	AllowedConnsCombinedStateful map[Node]map[Node]*common.ConnectionSet
}

func getCombinedConnsStr(combinedConns map[Node]map[Node]*common.ConnectionSet) string {
	strList := []string{}
	for src, nodeConns := range combinedConns {
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
	return strings.Join(strList, "")

}

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
	/*strList = []string{}
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
	res += strings.Join(strList, "")*/
	res += getCombinedConnsStr(v.AllowedConnsCombined)

	res += "=================================== stateful combined connections - short version:\n"
	res += getCombinedConnsStr(v.AllowedConnsCombinedStateful)
	return res
}

// GetVPCNetworkConnectivity computes VPCConnectivity in two steps
// (1) compute AllowedConns (map[Node]*ConnectivityResult) : ingress or egress allowed conns separately
// (2) compute AllowedConnsCombined (map[Node]map[Node]*common.ConnectionSet) : allowed conns considering both ingress and egress directions
func (v *CloudConfig) GetVPCNetworkConnectivity() *VPCConnectivity {
	res := &VPCConnectivity{
		AllowedConns:         map[Node]*ConnectivityResult{},
		AllowedConnsPerLayer: map[Node]map[string]*ConnectivityResult{},
	}
	// get connectivity in level of nodes elements
	for _, node := range v.Nodes {
		if node.IsInternal() {
			allIngressAllowedConns, ingressAllowedConnsPerLayer := v.getAllowedConnsPerDirection(true, node)
			allEgressAllowedConns, egressAllowedConnsPerLayer := v.getAllowedConnsPerDirection(false, node)

			res.AllowedConns[node] = &ConnectivityResult{
				IngressAllowedConns: allIngressAllowedConns,
				EgressAllowedConns:  allEgressAllowedConns,
			}
			res.AllowedConnsPerLayer[node] = map[string]*ConnectivityResult{}
			for layer := range ingressAllowedConnsPerLayer {
				res.AllowedConnsPerLayer[node][layer] = &ConnectivityResult{
					IngressAllowedConns: ingressAllowedConnsPerLayer[layer],
				}
			}
			for layer := range egressAllowedConnsPerLayer {
				res.AllowedConnsPerLayer[node][layer].EgressAllowedConns = egressAllowedConnsPerLayer[layer]
			}
		}
	}
	res.computeAllowedConnsCombined()
	res.computeAllowedStatefulConnections()
	return res
}

// "NaclLayer"
func (v *VPCConnectivity) getPerLayerConnectivity(layer string, src, dst Node, isIngress bool) *common.ConnectionSet {
	// TODO : what if one of the input nodes is not internal?
	var connMap map[string]*ConnectivityResult
	if isIngress {
		connMap = v.AllowedConnsPerLayer[dst]
	} else {
		connMap = v.AllowedConnsPerLayer[src]
	}
	connResult := connMap[layer]
	if isIngress {
		return connResult.IngressAllowedConns[src]
	}
	return connResult.EgressAllowedConns[dst]
}

func (v *VPCConnectivity) computeAllowedStatefulConnections() {
	// assuming v.AllowedConnsCombined was already computed

	// allowed connection: src->dst , requires NACL layer to allow dst->src (both ingress and egress)
	// on overlapping/matching connection-set, (src-dst ports should be switched??),
	// for it to be considered as stateful

	v.AllowedConnsCombinedStateful = map[Node]map[Node]*common.ConnectionSet{}

	for src, connsMap := range v.AllowedConnsCombined {
		for dst, conn := range connsMap {
			// get the allowed *stateful* conn result
			// check allowed conns per NACL-layer from dst to src (dst->src)
			var DstAllowedEgressToSrc, SrcAllowedIngressFromDst *common.ConnectionSet
			//can dst egress to src?
			DstAllowedEgressToSrc = v.getPerLayerConnectivity("NaclLayer", dst, src, false)
			//can src ingress from dst?
			SrcAllowedIngressFromDst = v.getPerLayerConnectivity("NaclLayer", dst, src, true)
			combinedDstToSrc := DstAllowedEgressToSrc.Intersection(SrcAllowedIngressFromDst)

			if _, ok := v.AllowedConnsCombinedStateful[src]; !ok {
				v.AllowedConnsCombinedStateful[src] = map[Node]*common.ConnectionSet{}
			}
			// TODO: flip src/dst ports before intersection?
			v.AllowedConnsCombinedStateful[src][dst] = conn.Intersection(combinedDstToSrc)
		}
	}
}

// computeAllowedConnsCombined computes combination of ingress&egress directions per connection allowed
// the result for this computation is stateless connections
// (could be that some of them or a subset of them are stateful,but this is not computed here)
func (v *VPCConnectivity) computeAllowedConnsCombined() {
	v.AllowedConnsCombined = map[Node]map[Node]*common.ConnectionSet{}

	for node, connectivityRes := range v.AllowedConns {
		for peerNode, conns := range connectivityRes.IngressAllowedConns {
			src := peerNode
			dst := node
			combinedConns := conns
			if peerNode.IsInternal() {
				egressConns := v.AllowedConns[peerNode].EgressAllowedConns[node]
				combinedConns = combinedConns.Intersection(egressConns)
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
				combinedConns = combinedConns.Intersection(ingressConss)
			}
			if _, ok := v.AllowedConnsCombined[src]; !ok {
				v.AllowedConnsCombined[src] = map[Node]*common.ConnectionSet{}
			}
			v.AllowedConnsCombined[src][dst] = combinedConns
		}
	}
}

func AllConns() *common.ConnectionSet {
	return common.NewConnectionSet(true)
}

func NoConns() *common.ConnectionSet {
	return common.NewConnectionSet(false)
}

func HasNode(listNodes []Node, node Node) bool {
	for _, n := range listNodes {
		if n.Cidr() == node.Cidr() {
			return true
		}
	}
	return false
}

func (v *CloudConfig) getAllowedConnsPerDirection(isIngress bool, capturedNode Node) (
	map[Node]*common.ConnectionSet, //result considering all layers
	map[string]map[Node]*common.ConnectionSet, //result separated per layer
) {
	perLayerRes := map[string]map[Node]*common.ConnectionSet{}
	allRes := map[Node]*common.ConnectionSet{}
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
				layerName := filter.Kind()
				filteredConns := filter.AllowedConnectivity(src, dst, isIngress)
				if _, ok := perLayerRes[layerName]; !ok {
					perLayerRes[layerName] = map[Node]*common.ConnectionSet{}
				}
				perLayerRes[layerName][peerNode] = filteredConns
				allowedConnsBetweenCapturedAndPeerNode = allowedConnsBetweenCapturedAndPeerNode.Intersection(filteredConns)
				// do not break if empty, to enable computation for all layers
				/*if allowedConnsBetweenCapturedAndPeerNode.IsEmpty() {
					break
				}*/
			}
			allRes[peerNode] = allowedConnsBetweenCapturedAndPeerNode
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
				layerName := filter.Kind()
				filteredConns := filter.AllowedConnectivity(src, dst, isIngress)
				if _, ok := perLayerRes[layerName]; !ok {
					perLayerRes[layerName] = map[Node]*common.ConnectionSet{}
				}
				perLayerRes[layerName][peerNode] = filteredConns
				allowedConnsBetweenCapturedAndPeerNode = allowedConnsBetweenCapturedAndPeerNode.Intersection(filteredConns)
				/*if allowedConnsBetweenCapturedAndPeerNode.IsEmpty() {
					break
				}*/
			}
			allRes[peerNode] = allowedConnsBetweenCapturedAndPeerNode
		}
	}
	return allRes, perLayerRes
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
