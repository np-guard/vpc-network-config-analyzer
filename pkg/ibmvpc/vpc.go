package ibmvpc

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
	vpcmodel "github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

// /////////////////////////////////////////////////////////////////////////////////////////////////
const (
	space                      = " "
	commaSeparator             = ","
	detailsAttributeUID        = "uid"
	detailsAttributeNodes      = "nodes"
	detailsAttributeAttachedTo = "attached_to"
	detailsAttributeSubnets    = "subnets"
	detailsAttributeMembers    = "members"
	detailsAttributeVSIname    = "vsiName"
	detailsAttributeAddress    = "address"
	detailsAttributeSubnetCIDR = "subnetCidr"
	detailsAttributeSubnetUID  = "subnetUID"
	detailsAttributeZone       = "zone"
	iksNodeKind                = "IKSNodeNetworkInterface"
)

func getNodeName(name, addr string) string {
	return fmt.Sprintf("%s[%s]", name, addr)
}

// ni.Kind() + space + ni.address + space + ni.Name() + " subnet: " + ni.subnet.cidr
func getNodeDetails(kind, addr, name, subnetCidr string) string {
	return kind + space + addr + space + name + " subnet: " + subnetCidr
}

// nodes elements - implement vpcmodel.Node interface
type NetworkInterface struct {
	vpcmodel.VPCResource
	address string
	vsi     string
	subnet  *Subnet
}

func (ni *NetworkInterface) Cidr() string {
	return ni.address
	// TODO: fix so that it works with cidr instead of address returned
	// return common.IPv4AddressToCidr(ni.address)
}
func (ni *NetworkInterface) IsInternal() bool {
	return true
}

func (ni *NetworkInterface) IsPublicInternet() bool {
	return false
}

func (ni *NetworkInterface) VsiName() string {
	return ni.vsi
}

func (ni *NetworkInterface) Kind() string {
	return "NetworkInterface"
}
func (ni *NetworkInterface) Name() string {
	return getNodeName(ni.vsi, ni.address)
}
func (ni *NetworkInterface) Details() []string {
	return []string{getNodeDetails(ni.Kind(), ni.address, ni.Name(), ni.subnet.cidr)}
}
func (ni *NetworkInterface) DetailsMap() []map[string]string {
	res := map[string]string{}
	res[vpcmodel.DetailsAttributeKind] = ni.Kind()
	res[vpcmodel.DetailsAttributeName] = ni.ResourceName
	res[detailsAttributeUID] = ni.ResourceUID
	res[detailsAttributeVSIname] = ni.vsi
	res[detailsAttributeAddress] = ni.address
	res[detailsAttributeSubnetCIDR] = ni.subnet.cidr
	res[detailsAttributeSubnetUID] = ni.subnet.ResourceUID
	return []map[string]string{res}
}

type IKSNode struct {
	vpcmodel.VPCResource
	address string
	subnet  *Subnet
}

func (n *IKSNode) Cidr() string {
	return n.address
}
func (n *IKSNode) IsInternal() bool {
	return true
}

func (n *IKSNode) IsPublicInternet() bool {
	return false
}

func (n *IKSNode) VsiName() string {
	return ""
}

func (n *IKSNode) Kind() string {
	return iksNodeKind
}
func (n *IKSNode) Name() string {
	return getNodeName(n.ResourceName, n.address)
}

func (n *IKSNode) Details() []string {
	return []string{getNodeDetails(n.Kind(), n.address, n.Name(), n.subnet.cidr)}
}

func (n *IKSNode) DetailsMap() []map[string]string {
	res := map[string]string{}
	res[vpcmodel.DetailsAttributeKind] = n.Kind()
	res[vpcmodel.DetailsAttributeName] = n.ResourceName
	res[detailsAttributeUID] = n.ResourceUID
	res[detailsAttributeAddress] = n.address
	res[detailsAttributeSubnetCIDR] = n.subnet.cidr
	res[detailsAttributeSubnetUID] = n.subnet.ResourceUID
	return []map[string]string{res}
}

/*type ReservedIP struct {
	name string
	cidr string
}


*/

///////////////////////////////////////////////////////////////////////////////////////////////////
// nodesets elements - implement vpcmodel.NodeSet interface

type VPC struct {
	vpcmodel.VPCResource
	nodes             []vpcmodel.Node
	connectivityRules *vpcmodel.ConnectivityResult // allowed connectivity between elements within the vpc
}

func (v *VPC) Nodes() []vpcmodel.Node {
	return v.nodes
}
func (v *VPC) Connectivity() *vpcmodel.ConnectivityResult {
	return v.connectivityRules
}

func (v *VPC) Details() []string {
	return []string{v.ResourceName}
}

func (v *VPC) Kind() string {
	return "VPC"
}

func (v *VPC) DetailsMap() []map[string]string {
	nodesUIDs := []string{}
	for _, node := range v.nodes {
		nodesUIDs = append(nodesUIDs, node.UID())
	}
	res := map[string]string{}
	res[vpcmodel.DetailsAttributeKind] = v.Kind()
	res[vpcmodel.DetailsAttributeName] = v.ResourceName
	res[detailsAttributeUID] = v.ResourceUID
	res[detailsAttributeNodes] = strings.Join(nodesUIDs, commaSeparator)
	return []map[string]string{res}
}

type Subnet struct {
	vpcmodel.VPCResource
	nodes             []vpcmodel.Node
	connectivityRules *vpcmodel.ConnectivityResult // allowed connectivity between elements within the subnet
	cidr              string
}

func (s *Subnet) Nodes() []vpcmodel.Node {
	return s.nodes
}
func (s *Subnet) Connectivity() *vpcmodel.ConnectivityResult {
	return s.connectivityRules
}
func (s *Subnet) Details() []string {
	return []string{s.ResourceName + space + s.cidr}
}

func (s *Subnet) Kind() string {
	return "Subnet"
}

func (s *Subnet) DetailsMap() []map[string]string {
	nodesUIDs := []string{}
	for _, node := range s.nodes {
		nodesUIDs = append(nodesUIDs, node.UID())
	}
	res := map[string]string{}
	res[vpcmodel.DetailsAttributeKind] = s.Kind()
	res[vpcmodel.DetailsAttributeName] = s.ResourceName
	res[detailsAttributeUID] = s.ResourceUID
	res[detailsAttributeNodes] = strings.Join(nodesUIDs, commaSeparator)
	res[vpcmodel.DetailsAttributeCIDR] = s.cidr
	res[detailsAttributeZone] = s.Zone
	return []map[string]string{res}
}

type Vsi struct {
	vpcmodel.VPCResource
	nodes             []vpcmodel.Node
	connectivityRules *vpcmodel.ConnectivityResult // possible rule: if has floating ip -> create connectivity to FIP, deny connectivity to PGW
}

func (v *Vsi) Nodes() []vpcmodel.Node {
	return v.nodes
}
func (v *Vsi) Connectivity() *vpcmodel.ConnectivityResult {
	return v.connectivityRules
}
func (v *Vsi) Details() []string {
	return []string{v.ResourceName}
}

func (v *Vsi) Kind() string {
	return "VSI"
}

func (v *Vsi) DetailsMap() []map[string]string {
	nodesUIDs := []string{}
	for _, node := range v.nodes {
		nodesUIDs = append(nodesUIDs, node.UID())
	}
	res := map[string]string{}
	res[vpcmodel.DetailsAttributeKind] = v.Kind()
	res[vpcmodel.DetailsAttributeName] = v.ResourceName
	res[detailsAttributeUID] = v.ResourceUID
	res[detailsAttributeNodes] = strings.Join(nodesUIDs, commaSeparator)
	res[detailsAttributeZone] = v.Zone
	return []map[string]string{res}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// FilterTraffic elements

type NaclLayer struct {
	vpcmodel.VPCResource
	naclList []*NACL
}

func (nl *NaclLayer) Kind() string {
	return vpcmodel.NaclLayer
}

func (nl *NaclLayer) Details() []string {
	res := []string{}
	for _, nacl := range nl.naclList {
		res = append(res, nacl.Details())
	}
	return res
}

func (nl *NaclLayer) DetailsMap() []map[string]string {
	res := []map[string]string{}
	for _, nacl := range nl.naclList {
		res = append(res, nacl.DetailsMap())
	}
	return res
}

// per-layer connectivity analysis
// compute allowed connectivity based on the NACL resources for all relevant endpoints (subnets)
func (nl *NaclLayer) ConnectivityMap() (map[string]*vpcmodel.IPbasedConnectivityResult, error) {
	res := map[string]*vpcmodel.IPbasedConnectivityResult{} // map from subnet cidr to its connectivity result
	for _, nacl := range nl.naclList {
		for subnetCidr := range nacl.subnets {
			_, resConnectivity := nacl.analyzer.GeneralConnectivityPerSubnet(subnetCidr)
			// TODO: currently supporting only handling full-range of subnet connectivity-map, not partial range of subnet
			if len(resConnectivity) != 1 {
				return nil, errors.New("unsupported connectivity map with partial subnet ranges per connectivity result")
			}
			subnetKey := common.CIDRtoIPrange(subnetCidr)
			if _, ok := resConnectivity[subnetKey]; !ok {
				return nil, errors.New("unexpected subnet connectivity result - key is different from subnet cidr")
			}
			res[subnetCidr] = resConnectivity[subnetKey]
		}
	}
	return res, nil
}

func (nl *NaclLayer) GetConnectivityOutputPerEachElemSeparately() string {
	res := []string{}
	// iterate over all subnets, collect all outputs per subnet connectivity
	for _, nacl := range nl.naclList {
		for subnet := range nacl.subnets {
			res = append(res, nacl.GeneralConnectivityPerSubnet(subnet))
		}
	}
	sort.Strings(res)
	return strings.Join(res, "\n")
}

func (nl *NaclLayer) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) (*common.ConnectionSet, error) {
	res := vpcmodel.NoConns()
	for _, nacl := range nl.naclList {
		naclConn, err := nacl.AllowedConnectivity(src, dst, isIngress)
		if err != nil {
			return nil, err
		}
		res = res.Union(naclConn)
	}
	return res, nil
}

func (nl *NaclLayer) ReferencedIPblocks() []*common.IPBlock {
	res := []*common.IPBlock{}
	for _, n := range nl.naclList {
		res = append(res, n.analyzer.referencedIPblocks...)
	}
	return res
}

type NACL struct {
	vpcmodel.VPCResource
	subnets  map[string]struct{} // map of subnet cidr strings for which this nacl is applied to
	analyzer *NACLAnalyzer
}

func (n *NACL) Kind() string {
	return "NACL"
}

func (n *NACL) Details() string {
	subnets := ""
	for subent := range n.subnets {
		subnets += subent + commaSeparator
	}
	return "NACL " + n.ResourceName + "subnets: " + subnets
}

func (n *NACL) DetailsMap() map[string]string {
	subnetList := make([]string, len(n.subnets))
	i := 0
	for s := range n.subnets {
		subnetList[i] = s
		i++
	}
	return map[string]string{
		vpcmodel.DetailsAttributeKind: n.Kind(),
		vpcmodel.DetailsAttributeName: n.ResourceName,
		detailsAttributeUID:           n.ResourceUID,
		detailsAttributeSubnets:       strings.Join(subnetList, commaSeparator),
	}
}

func (n *NACL) GeneralConnectivityPerSubnet(subnetCidr string) string {
	res, _ := n.analyzer.GeneralConnectivityPerSubnet(subnetCidr)
	return res
}

func getNodeCidrs(n vpcmodel.Node) (subnetCidr, nodeCidr string, err error) {
	switch t := n.(type) {
	case *NetworkInterface:
		return t.subnet.cidr, t.Cidr(), nil
	case *IKSNode:
		return t.subnet.cidr, t.Cidr(), nil
	default:
		return "", "", fmt.Errorf("cannot get cidr for node: %s", n)
	}
}

func (n *NACL) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) (*common.ConnectionSet, error) {
	var subnetCidr string
	var inSubnetCidr string
	var targetNode vpcmodel.Node
	var err error
	if isIngress {
		targetNode = src
		subnetCidr, inSubnetCidr, err = getNodeCidrs(dst)
	} else {
		targetNode = dst
		subnetCidr, inSubnetCidr, err = getNodeCidrs(src)
	}
	if err != nil {
		return nil, err
	}
	// check if the subnet of the given node is affected by this nacl
	if _, ok := n.subnets[subnetCidr]; !ok {
		return vpcmodel.NoConns(), nil // not affected by current nacl
	}
	// TODO: differentiate between "has no effect" vs "affects with allow-all / allow-none "
	if allInSubnet, err := common.IsAddressInSubnet(targetNode.Cidr(), subnetCidr); err == nil && allInSubnet {
		return vpcmodel.AllConns(), nil // nacl has no control on traffic between two instances in its subnet
	}
	// TODO: consider err
	res, _ := n.analyzer.AllowedConnectivity(subnetCidr, inSubnetCidr, targetNode.Cidr(), isIngress)
	return res, nil
}

// SecurityGroupLayer captures all SG in the vpc config, analyzes connectivity considering all SG resources
type SecurityGroupLayer struct {
	vpcmodel.VPCResource
	sgList []*SecurityGroup
}

func (sgl *SecurityGroupLayer) Name() string {
	return ""
}

func (sgl *SecurityGroupLayer) Kind() string {
	return vpcmodel.SecurityGroupLayer
}

func (sgl *SecurityGroupLayer) Details() []string {
	res := []string{}
	for _, sg := range sgl.sgList {
		res = append(res, sg.Details())
	}
	return res
}

func (sgl *SecurityGroupLayer) DetailsMap() []map[string]string {
	res := []map[string]string{}
	for _, sg := range sgl.sgList {
		res = append(res, sg.DetailsMap())
	}
	return res
}

func (sgl *SecurityGroupLayer) ConnectivityMap() (map[string]*vpcmodel.IPbasedConnectivityResult, error) {
	return nil, nil
}

func (sgl *SecurityGroupLayer) GetConnectivityOutputPerEachElemSeparately() string {
	return ""
}

// TODO: fix: is it possible that no sg applies  to the input peer? if so, should not return "no conns" when none applies
func (sgl *SecurityGroupLayer) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) (*common.ConnectionSet, error) {
	if (isIngress && dst.Kind() == iksNodeKind) || (!isIngress && src.Kind() == iksNodeKind) {
		return vpcmodel.AllConns(), nil
	}
	res := vpcmodel.NoConns()
	for _, sg := range sgl.sgList {
		sgConn := sg.AllowedConnectivity(src, dst, isIngress)
		res = res.Union(sgConn)
	}
	return res, nil
}

func (sgl *SecurityGroupLayer) ReferencedIPblocks() []*common.IPBlock {
	res := []*common.IPBlock{}
	for _, sg := range sgl.sgList {
		res = append(res, sg.analyzer.referencedIPblocks...)
	}
	return res
}

type SecurityGroup struct {
	vpcmodel.VPCResource
	analyzer *SGAnalyzer
	members  map[string]struct{} // map of members as their address string values

}

func (sg *SecurityGroup) Kind() string {
	return "SG"
}

func (sg *SecurityGroup) Details() string {
	members := ""
	for member := range sg.members {
		members += member + commaSeparator
	}
	return "SG " + sg.ResourceName + " members: " + members
}

func (sg *SecurityGroup) DetailsMap() map[string]string {
	membersList := make([]string, len(sg.members))
	i := 0
	for s := range sg.members {
		membersList[i] = s
		i++
	}
	return map[string]string{
		vpcmodel.DetailsAttributeKind: sg.Kind(),
		vpcmodel.DetailsAttributeName: sg.ResourceName,
		detailsAttributeUID:           sg.ResourceUID,
		detailsAttributeMembers:       strings.Join(membersList, commaSeparator),
	}
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
		return vpcmodel.NoConns() // connectivity not affected by this SG resource - input node is not its member
	}
	targetStrAddress := target.Cidr()
	return sg.analyzer.AllowedConnectivity(targetStrAddress, isIngress)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func getRouterAttachedToStr(attachedDetails string) string {
	return " attached to: " + attachedDetails
}

// routing resource elements

type FloatingIP struct {
	vpcmodel.VPCResource
	cidr         string
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
}

func (fip *FloatingIP) Details() []string {
	attachedDetails := ""
	for _, n := range fip.src {
		attachedDetails += n.Name() + commaSeparator
	}
	return []string{"FloatingIP " + fip.ResourceName + getRouterAttachedToStr(attachedDetails)}
}

func (fip *FloatingIP) Kind() string {
	return "FloatingIP"
}

func (fip *FloatingIP) DetailsMap() []map[string]string {
	attachedDetails := ""
	for _, n := range fip.src {
		attachedDetails += n.UID() + commaSeparator
	}
	res := map[string]string{
		vpcmodel.DetailsAttributeName: fip.ResourceName,
		detailsAttributeUID:           fip.ResourceUID,
		vpcmodel.DetailsAttributeKind: fip.Kind(),
		detailsAttributeAttachedTo:    attachedDetails,
		vpcmodel.DetailsAttributeCIDR: fip.cidr,
		detailsAttributeZone:          fip.Zone,
	}
	return []map[string]string{res}
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

func (fip *FloatingIP) AppliedFiltersKinds() map[string]bool {
	return map[string]bool{vpcmodel.SecurityGroupLayer: true}
}

func (fip *FloatingIP) ConnectivityMap() map[string]vpcmodel.ConfigBasedConnectivityResults {
	return nil
}

type PublicGateway struct {
	vpcmodel.VPCResource
	cidr         string
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
	subnetCidr   []string
}

func (pgw *PublicGateway) Details() []string {
	attachedDetails := ""
	for _, n := range pgw.src {
		attachedDetails += n.Name() + commaSeparator
	}
	subnets := strings.Join(pgw.subnetCidr, ",")
	return []string{"PublicGateway " + pgw.ResourceName + " nodes " + getRouterAttachedToStr(attachedDetails) + " subnets: " + subnets}
}

func (pgw *PublicGateway) Kind() string {
	return "PublicGateway"
}

func (pgw *PublicGateway) DetailsMap() []map[string]string {
	attachedDetails := ""
	for _, n := range pgw.src {
		attachedDetails += n.UID() + commaSeparator
	}
	res := map[string]string{
		vpcmodel.DetailsAttributeName: pgw.ResourceName,
		detailsAttributeUID:           pgw.ResourceUID,
		vpcmodel.DetailsAttributeKind: pgw.Kind(),
		detailsAttributeAttachedTo:    attachedDetails,
		vpcmodel.DetailsAttributeCIDR: pgw.cidr,
		detailsAttributeZone:          pgw.Zone,
	}
	return []map[string]string{res}
}

func (pgw *PublicGateway) ConnectivityMap() map[string]vpcmodel.ConfigBasedConnectivityResults {
	res := map[string]vpcmodel.ConfigBasedConnectivityResults{}
	for _, subnetCidr := range pgw.subnetCidr {
		res[subnetCidr] = vpcmodel.ConfigBasedConnectivityResults{
			IngressAllowedConns: map[string]*common.ConnectionSet{},
			EgressAllowedConns:  map[string]*common.ConnectionSet{},
		}
		for _, dst := range pgw.destinations {
			res[subnetCidr].EgressAllowedConns[dst.Name()] = vpcmodel.AllConns()
		}
	}

	return res
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

func (pgw *PublicGateway) AppliedFiltersKinds() map[string]bool {
	return map[string]bool{vpcmodel.NaclLayer: true, vpcmodel.SecurityGroupLayer: true}
}
