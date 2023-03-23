package ibmvpc

import (
	"fmt"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcModel"
)

///////////////////////////////////////////////////////////////////////////////////////////////////
// nodes elements - implement vpcmodel.Node interface

type NetworkInterface struct {
	name   string
	cidr   string
	vsi    string
	subnet *Subnet
}

/*type ReservedIP struct {
	name string
	cidr string
}


*/

type ExternalNetwork struct {
	name string
	cidr string
}

func (ni *NetworkInterface) Name() string {
	return fmt.Sprintf("%s[%s]", ni.vsi, ni.name) //ni.name
}
func (ni *NetworkInterface) Cidr() string {
	return ni.cidr
}
func (ni *NetworkInterface) IsInternal() bool {
	return true
}
func (ni *NetworkInterface) VsiName() string {
	return ni.vsi
}

/*
func (rip *ReservedIP) Name() string {
	return rip.name
}
func (rip *ReservedIP) Cidr() string {
	return rip.cidr
}


*/

func (exn *ExternalNetwork) Name() string {
	return exn.name
}
func (exn *ExternalNetwork) Cidr() string {
	return exn.cidr
}
func (exn *ExternalNetwork) IsInternal() bool {
	return false
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// nodesets elements - implement vpcmodel.NodeSet interface

type VPC struct {
	name              string
	nodes             []vpcmodel.Node
	connectivityRules *vpcmodel.ConnectivityResult //allowed connectivity between elements within the vpc
}

type Subnet struct {
	name              string
	nodes             []vpcmodel.Node
	connectivityRules *vpcmodel.ConnectivityResult //allowed connectivity between elements within the subnet
	cidr              string
}

type Vsi struct {
	name              string
	nodes             []vpcmodel.Node
	connectivityRules *vpcmodel.ConnectivityResult // possible rule: if has floating ip -> create connectivity to FIP, deny connectivity to PGW
}

func (v *VPC) Name() string {
	return v.name
}

func (v *VPC) Nodes() []vpcmodel.Node {
	return v.nodes
}
func (v *VPC) Connectivity() *vpcmodel.ConnectivityResult {
	return v.connectivityRules
}

func (s *Subnet) Name() string {
	return s.name
}

func (s *Subnet) Nodes() []vpcmodel.Node {
	return s.nodes
}
func (s *Subnet) Connectivity() *vpcmodel.ConnectivityResult {
	return s.connectivityRules
}

func (v *Vsi) Name() string {
	return v.name
}

func (v *Vsi) Nodes() []vpcmodel.Node {
	return v.nodes
}
func (v *Vsi) Connectivity() *vpcmodel.ConnectivityResult {
	return v.connectivityRules
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// FilterTraffic elements

type NACL struct {
	name              string
	inboundRules      []vpcmodel.FilterTrafficRule
	outboundRules     []vpcmodel.FilterTrafficRule
	subnets           map[string]struct{} // map of subnet cidr strings for which this nacl is applied to
	connectivityRules map[vpcmodel.NodeSet]*vpcmodel.ConnectivityResult
	analyzer          *NACLAnalyzer
}

func (n *NACL) Name() string {
	return n.name
}

func (n *NACL) InboundRules() []vpcmodel.FilterTrafficRule {
	return n.inboundRules
}

func (n *NACL) OutboundRules() []vpcmodel.FilterTrafficRule {
	return n.outboundRules
}

func (n *NACL) Connectivity(nodes vpcmodel.NodeSet) *vpcmodel.ConnectivityResult {
	return n.connectivityRules[nodes]
}

func (n *NACL) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *common.ConnectionSet {
	var subnetCidr string
	var inSubnetCidr string
	var targetNode vpcmodel.Node
	if isIngress {
		targetNode = src
		if dstInstance, ok := dst.(*NetworkInterface); ok {
			subnetCidr = dstInstance.subnet.cidr
			inSubnetCidr = dst.Cidr()
		}
	} else {
		targetNode = dst
		if srcInstance, ok := src.(*NetworkInterface); ok {
			subnetCidr = srcInstance.subnet.cidr
			inSubnetCidr = src.Cidr()
		}
	}
	// check if the subnet of the given node is affected by this nacl
	if _, ok := n.subnets[subnetCidr]; !ok {
		return vpcmodel.AllConns() // not affected by current nacl
	}

	return n.analyzer.AllowedConnectivity(subnetCidr, inSubnetCidr, targetNode.Cidr(), isIngress)

	//return vpcmodel.AllConns()
}

type SecurityGroup struct {
	name          string
	inboundRules  []vpcmodel.FilterTrafficRule
	outboundRules []vpcmodel.FilterTrafficRule
	//netInterfaces     []NetworkInterface
	connectivityRules *vpcmodel.ConnectivityResult
	analyzer          *SGAnalyzer
	members           map[string]struct{} //map of members as their address string values
}

func (sg *SecurityGroup) Name() string {
	return sg.name
}

func (sg *SecurityGroup) InboundRules() []vpcmodel.FilterTrafficRule {
	return sg.inboundRules
}

func (sg *SecurityGroup) OutboundRules() []vpcmodel.FilterTrafficRule {
	return sg.outboundRules
}

func (sg *SecurityGroup) Connectivity(nodes vpcmodel.NodeSet) *vpcmodel.ConnectivityResult {
	return sg.connectivityRules
}

func (sg *SecurityGroup) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *common.ConnectionSet {
	var member, target vpcmodel.Node
	if isIngress {
		member = dst
		target = src
	} else {
		member = src
		target = dst
	}
	memberStrAddress := member.Cidr()
	if _, ok := sg.members[memberStrAddress]; !ok {
		return vpcmodel.AllConns() // connectivity not affected by this SG resource - input node is not its member
	}
	targetStrAddress := target.Cidr()
	return sg.analyzer.AllowedConnectivity(targetStrAddress, isIngress)

	//return vpcmodel.AllConns()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

// routing resource elements

type FloatingIP struct {
	name         string
	cidr         string
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
}

type PublicGateway struct {
	name         string
	cidr         string
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
}

func (fip *FloatingIP) Name() string {
	return fip.name
}
func (fip *FloatingIP) Src() []vpcmodel.Node {
	return fip.src
}
func (fip *FloatingIP) Destinations() []vpcmodel.Node {
	return fip.destinations
}

func (fip *FloatingIP) AllowedConnectivity(src, dst vpcmodel.Node) *common.ConnectionSet {
	if vpcmodel.HasNode(fip.Src(), src) && vpcmodel.HasNode(fip.Destinations(), dst) {
		return vpcmodel.AllConns()
	}
	if vpcmodel.HasNode(fip.Src(), dst) && vpcmodel.HasNode(fip.Destinations(), src) {
		return vpcmodel.AllConns()
	}
	return vpcmodel.NoConns()

}

func (pgw *PublicGateway) Name() string {
	return pgw.name
}
func (pgw *PublicGateway) Src() []vpcmodel.Node {
	return pgw.src
}
func (pgw *PublicGateway) Destinations() []vpcmodel.Node {
	return pgw.destinations
}

func (pgw *PublicGateway) AllowedConnectivity(src, dst vpcmodel.Node) *common.ConnectionSet {
	if vpcmodel.HasNode(pgw.Src(), src) && vpcmodel.HasNode(pgw.Destinations(), dst) {
		return vpcmodel.AllConns()
	}
	return vpcmodel.NoConns()

}

///////////////////////////////////////////////////////////////////////////////////////////////////

/*func GetVPCNetworkConnectivity(vpcConfig *vpcmodel.VPCConfig) *vpcmodel.VPCConnectivity {
	res := &vpcmodel.VPCConnectivity{AllowedConns: map[vpcmodel.Node]*vpcmodel.ConnectivityResult{}}
	// get connectivity in level of nodes elements
	for _, node := range vpcConfig.Nodes {
		if node.IsInternal() { //if _, ok := node.(*NetworkInterface); ok {
			res.AllowedConns[node] = &vpcmodel.ConnectivityResult{
				IngressAllowedConns: map[vpcmodel.Node]*common.ConnectionSet{},
				EgressAllowedConns:  map[vpcmodel.Node]*common.ConnectionSet{},
			}
		}
	}
	return res
}

func getAllowedConnsPerDirection(isIngress bool, capturedNode vpcmodel.Node, vpcConfig *vpcmodel.VPCConfig) {
	for _, peerNode := range vpcConfig.Nodes {
		if peerNode.IsInternal() {
			// no need for router node, connectivity is from within VPC
			// only check filtering resources
		}
	}
}*/

/*
// implement interface vpcmodel.Vpc
type vpc struct {
	name   string
	cidr   string
	region string
}

func (v *vpc) Name() string {
	return v.name
}
func (v *vpc) Cidr() string {
	return v.cidr
}
func (v *vpc) Region() string {
	return v.region
}

func NewVPC(name, cidr, region string) vpcmodel.Vpc {
	vpc := &vpc{name: name, cidr: cidr, region: region}
	return vpc
}

//implement interface vpcmodel.Zone
type zone struct {
	name string
	cidr string
	vpc  vpcmodel.Vpc
}

func (z *zone) Name() string {
	return z.name
}
func (z *zone) Cidr() string {
	return z.cidr
}
func (z *zone) VPC() vpcmodel.Vpc {
	return z.vpc
}

func NewZone(name, cidr string, vpc vpcmodel.Vpc) vpcmodel.Zone {
	return &zone{name: name, cidr: cidr, vpc: vpc}
}

// implement interface vpcmodel.NetworkInterface
type NWInterface struct {
	name    string
	address string
	subnet  *subnet
}

func (i *NWInterface) Name() string {
	return i.name
}
func (i *NWInterface) Address() string {
	return i.address
}

func (i *NWInterface) Subnet() vpcmodel.Subnet {
	return i.subnet
}

func NewNwInterface(name, address string, subnet *subnet) vpcmodel.NetworkInterface {
	return &NWInterface{name: name, address: address, subnet: subnet}
}

// implement interface vpcmodel.Instance
type vsi struct {
	name         string
	nwInterfaces []*NWInterface
	zone         *zone
}

func (v *vsi) Name() string {
	return v.name
}

func (v *vsi) Zone() vpcmodel.Zone {
	return v.zone
}

func (v *vsi) NetworkInterfaces() []vpcmodel.NetworkInterface {
	res := make([]vpcmodel.NetworkInterface, len(v.nwInterfaces))
	for i := range v.nwInterfaces {
		res[i] = v.nwInterfaces[i]
	}
	return res
}

func NewVSI(name string, nwInterfaces []*NWInterface, zone *zone) vpcmodel.Instance {
	return &vsi{name: name, nwInterfaces: nwInterfaces, zone: zone}
}
*/

/*
type Subnet interface {
	Name() string
	Cidr() string
	Zone() Zone
}
*/
/*
// implement interface vpcmodel.subnet
type subnet struct {
	name string
	cidr string
	zone *zone
}

func (s *subnet) Name() string {
	return s.name
}

func (s *subnet) Cidr() string {
	return s.cidr
}

func (s *subnet) Zone() vpcmodel.Zone {
	return s.zone
}

func NewSubnet(name, cidr string, zone *zone) *subnet {
	return &subnet{name: name, cidr: cidr, zone: zone}
}
*/
