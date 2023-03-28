package ibmvpc

import (
	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcModel"
)

type namedResource struct {
	name string
	uid  string
}

func (n *namedResource) Name() string {
	return n.name
}

func (n *namedResource) UID() string {
	return n.uid
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// nodes elements - implement vpcmodel.Node interface

type NetworkInterface struct {
	namedResource
	cidr   string
	vsi    string
	subnet *Subnet
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

/*type ReservedIP struct {
	name string
	cidr string
}


*/

type ExternalNetwork struct {
	namedResource
	cidr string
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
	namedResource
	nodes             []vpcmodel.Node
	connectivityRules *vpcmodel.ConnectivityResult //allowed connectivity between elements within the vpc
}

func (v *VPC) Nodes() []vpcmodel.Node {
	return v.nodes
}
func (v *VPC) Connectivity() *vpcmodel.ConnectivityResult {
	return v.connectivityRules
}

type Subnet struct {
	namedResource
	nodes             []vpcmodel.Node
	connectivityRules *vpcmodel.ConnectivityResult //allowed connectivity between elements within the subnet
	cidr              string
}

func (s *Subnet) Nodes() []vpcmodel.Node {
	return s.nodes
}
func (s *Subnet) Connectivity() *vpcmodel.ConnectivityResult {
	return s.connectivityRules
}

type Vsi struct {
	namedResource
	nodes             []vpcmodel.Node
	connectivityRules *vpcmodel.ConnectivityResult // possible rule: if has floating ip -> create connectivity to FIP, deny connectivity to PGW
}

func (v *Vsi) Nodes() []vpcmodel.Node {
	return v.nodes
}
func (v *Vsi) Connectivity() *vpcmodel.ConnectivityResult {
	return v.connectivityRules
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// FilterTraffic elements

type NaclLayer struct {
	namedResource
	naclList []*NACL
}

func (nl *NaclLayer) Kind() string {
	return "SecurityGroupLayer"
}

func (nl *NaclLayer) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *common.ConnectionSet {
	res := vpcmodel.NoConns()
	for _, nacl := range nl.naclList {
		naclConn := nacl.AllowedConnectivity(src, dst, isIngress)
		res.Union(*naclConn)
	}
	return res
}

func (nl *NaclLayer) ReferencedIPblocks() []*common.IPBlock {
	res := []*common.IPBlock{}
	for _, n := range nl.naclList {
		res = append(res, n.analyzer.referencedIPblocks...)
	}
	return res
}

type NACL struct {
	namedResource
	subnets  map[string]struct{} // map of subnet cidr strings for which this nacl is applied to
	analyzer *NACLAnalyzer
}

func (n *NACL) Kind() string {
	return "NACL"
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
		//return vpcmodel.AllConns() // not affected by current nacl
		return vpcmodel.NoConns() // not affected by current nacl
	}

	return n.analyzer.AllowedConnectivity(subnetCidr, inSubnetCidr, targetNode.Cidr(), isIngress)

	//return vpcmodel.AllConns()
}

// SecurityGroupLayer captures all SG in the vpc config, analyzes connectivity considering all SG resources
type SecurityGroupLayer struct {
	namedResource
	sgList []*SecurityGroup
}

func (sgl *SecurityGroupLayer) Name() string {
	return ""
}

func (sgl *SecurityGroupLayer) Kind() string {
	return "SecurityGroupLayer"
}

// TODO: fix: is it possible that no sg applies  to the input peer? if so, should not return "no conns" when none applies
func (sgl *SecurityGroupLayer) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *common.ConnectionSet {
	res := vpcmodel.NoConns()
	for _, sg := range sgl.sgList {
		sgConn := sg.AllowedConnectivity(src, dst, isIngress)
		res.Union(*sgConn)
	}
	return res
}

func (sgl *SecurityGroupLayer) ReferencedIPblocks() []*common.IPBlock {
	res := []*common.IPBlock{}
	for _, sg := range sgl.sgList {
		res = append(res, sg.analyzer.referencedIPblocks...)
	}
	return res
}

type SecurityGroup struct {
	namedResource
	analyzer *SGAnalyzer
	members  map[string]struct{} //map of members as their address string values

}

func (sg *SecurityGroup) Kind() string {
	return "SG"
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
		//return vpcmodel.AllConns() // connectivity not affected by this SG resource - input node is not its member
		return vpcmodel.NoConns() // connectivity not affected by this SG resource - input node is not its member
	}
	targetStrAddress := target.Cidr()
	return sg.analyzer.AllowedConnectivity(targetStrAddress, isIngress)

	//return vpcmodel.AllConns()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

// routing resource elements

type FloatingIP struct {
	namedResource
	cidr         string
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
}

type PublicGateway struct {
	namedResource
	cidr         string
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
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
