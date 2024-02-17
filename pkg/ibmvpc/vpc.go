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
const semicolonSeparator = "; "

const networkACLStr = "network ACL "
const securityGroupStr = "security group "

func getNodeName(name, addr string) string {
	return fmt.Sprintf("%s[%s]", name, addr)
}

type Zone struct {
	name string
	vpc  *VPC
}

func (z *Zone) VPC() *VPC {
	return z.vpc
}

func zoneFromVPCResource(r vpcmodel.VPCResourceIntf) (*Zone, error) {
	if vpc, ok := r.VPC().(*VPC); ok {
		return vpc.getZoneByName(r.ZoneName())
	}
	return nil, errors.New("error getting VPC from resource object")
}

// ReservedIP implements vpcmodel.Node interface
type ReservedIP struct {
	vpcmodel.VPCResource
	address string
	ipblock *common.IPBlock
	subnet  *Subnet
	vpe     string
}

func (r *ReservedIP) CidrOrAddress() string {
	return r.address
	// TODO: fix so that it works with cidr instead of address returned
	// return common.IPv4AddressToCidr(ni.address)
}

func (r *ReservedIP) IPBlock() *common.IPBlock {
	return r.ipblock
}

func (r *ReservedIP) IsInternal() bool {
	return true
}

func (r *ReservedIP) IsPublicInternet() bool {
	return false
}

func (r *ReservedIP) Name() string {
	return getNodeName(r.vpe, r.address)
}

// NetworkInterface implements vpcmodel.Node interface
type NetworkInterface struct {
	vpcmodel.VPCResource
	address string
	vsi     string
	subnet  *Subnet
	ipblock *common.IPBlock
}

func (ni *NetworkInterface) CidrOrAddress() string {
	return ni.address
	// TODO: fix so that it works with cidr instead of address returned
	// return common.IPv4AddressToCidr(ni.address)
}

func (ni *NetworkInterface) IPBlock() *common.IPBlock {
	return ni.ipblock
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

func (ni *NetworkInterface) Name() string {
	return getNodeName(ni.vsi, ni.address)
}

// IKSNode implements vpcmodel.Node interface
type IKSNode struct {
	vpcmodel.VPCResource
	address string
	ipblock *common.IPBlock
	subnet  *Subnet
}

func (n *IKSNode) CidrOrAddress() string {
	return n.address
}

func (n *IKSNode) IPBlock() *common.IPBlock {
	return n.ipblock
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

func (n *IKSNode) Name() string {
	return getNodeName(n.ResourceName, n.address)
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// nodesets elements - implement vpcmodel.NodeSet interface

type VPC struct {
	vpcmodel.VPCResource
	nodes                []vpcmodel.Node
	connectivityRules    *vpcmodel.ConnectivityResult // allowed connectivity between elements within the vpc
	zones                map[string]*Zone
	internalAddressRange *common.IPBlock
	subnetsList          []*Subnet
	addressPrefixes      []string
}

func (v *VPC) getZoneByName(name string) (*Zone, error) {
	if z, ok := v.zones[name]; ok {
		return z, nil
	}
	return nil, fmt.Errorf("zone %s not found in vpc %s", name, v.ResourceName)
}

func (v *VPC) Nodes() []vpcmodel.Node {
	return v.nodes
}
func (v *VPC) Connectivity() *vpcmodel.ConnectivityResult {
	return v.connectivityRules
}

func (v *VPC) AddressRange() *common.IPBlock {
	return v.internalAddressRange
}

func (v *VPC) subnets() []*Subnet {
	return v.subnetsList
}

type Subnet struct {
	vpcmodel.VPCResource
	nodes             []vpcmodel.Node
	connectivityRules *vpcmodel.ConnectivityResult // allowed connectivity between elements within the subnet
	cidr              string
	ipblock           *common.IPBlock
}

func (s *Subnet) Zone() (*Zone, error) {
	return zoneFromVPCResource(s)
}

func (s *Subnet) Nodes() []vpcmodel.Node {
	return s.nodes
}

func (s *Subnet) AddressRange() *common.IPBlock {
	return s.ipblock
}

func (s *Subnet) Connectivity() *vpcmodel.ConnectivityResult {
	return s.connectivityRules
}

type Vsi struct {
	vpcmodel.VPCResource
	nodes             []vpcmodel.Node
	connectivityRules *vpcmodel.ConnectivityResult // possible rule: if has floating ip -> create connectivity to FIP, deny connectivity to PGW
}

func (v *Vsi) Zone() (*Zone, error) {
	return zoneFromVPCResource(v)
}

func (v *Vsi) Nodes() []vpcmodel.Node {
	return v.nodes
}

func (v *Vsi) Connectivity() *vpcmodel.ConnectivityResult {
	return v.connectivityRules
}

func (v *Vsi) AddressRange() *common.IPBlock {
	return nodesAddressRange(v.nodes)
}

func nodesAddressRange(nodes []vpcmodel.Node) *common.IPBlock {
	var res *common.IPBlock
	for _, n := range nodes {
		if res == nil {
			res = n.IPBlock()
		} else {
			res = res.Union(n.IPBlock())
		}
	}
	return res
}

// vpe can be in multiple zones - depending on the zones of its network interfaces..
type Vpe struct {
	vpcmodel.VPCResource
	nodes []vpcmodel.Node
}

func (v *Vpe) Nodes() []vpcmodel.Node {
	return v.nodes
}

func (v *Vpe) Connectivity() *vpcmodel.ConnectivityResult {
	return nil
}

func (v *Vpe) AddressRange() *common.IPBlock {
	return nodesAddressRange(v.nodes)
}

// vpe is per vpc and not per zone...
func (v *Vpe) Zone() (*Zone, error) {
	return nil, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// FilterTraffic elements

type NaclLayer struct {
	vpcmodel.VPCResource
	naclList []*NACL
}

// per-layer connectivity analysis
// compute allowed connectivity based on the NACL resources for all relevant endpoints (subnets)
func (nl *NaclLayer) ConnectivityMap() (map[string]*vpcmodel.IPbasedConnectivityResult, error) {
	res := map[string]*vpcmodel.IPbasedConnectivityResult{} // map from subnet cidr to its connectivity result
	for _, nacl := range nl.naclList {
		for subnetCidr, subnet := range nacl.subnets {
			_, resConnectivity := nacl.analyzer.GeneralConnectivityPerSubnet(subnet)
			// TODO: currently supporting only handling full-range of subnet connectivity-map, not partial range of subnet
			if len(resConnectivity) != 1 {
				return nil, errors.New("unsupported connectivity map with partial subnet ranges per connectivity result")
			}
			subnetKey := subnet.ipblock.ToIPRanges()
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
		for _, subnet := range nacl.subnets {
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

// RulesInConnectivity list of NACL rules contributing to the connectivity
func (nl *NaclLayer) RulesInConnectivity(src, dst vpcmodel.Node,
	conn *common.ConnectionSet, isIngress bool) (allowRes []vpcmodel.RulesInFilter,
	denyRes []vpcmodel.RulesInFilter, err error) {
	for index, nacl := range nl.naclList {
		tableRelevant, allowRules, denyRules, err1 := nacl.rulesFilterInConnectivity(src, dst, conn, isIngress)
		if err1 != nil {
			return nil, nil, err1
		}
		if !tableRelevant {
			continue
		}
		appendToRulesInFilter(&allowRes, &allowRules, index, true)
		appendToRulesInFilter(&denyRes, &denyRules, index, false)
	}
	return allowRes, denyRes, nil
}

func appendToRulesInFilter(resRulesInFilter *[]vpcmodel.RulesInFilter, rules *[]int, filterIndex int, isAllow bool) {
	var rType vpcmodel.RulesType
	switch {
	case len(*rules) == 0:
		rType = vpcmodel.NoRules
	case len(*rules) == 1 && (*rules)[0] == vpcmodel.DummyRule:
		rType = vpcmodel.OnlyDummyRule
	case isAllow:
		rType = vpcmodel.OnlyAllow
	default: // more than 0 deny rules
		rType = vpcmodel.OnlyDeny
	}
	rulesInNacl := vpcmodel.RulesInFilter{
		Filter:          filterIndex,
		Rules:           *rules,
		RulesFilterType: rType,
	}
	*resRulesInFilter = append(*resRulesInFilter, rulesInNacl)
}

func (nl *NaclLayer) StringDetailsRulesOfFilter(listRulesInFilter []vpcmodel.RulesInFilter) string {
	strListRulesInFilter := ""
	for _, rulesInFilter := range listRulesInFilter {
		nacl := nl.naclList[rulesInFilter.Filter]
		header := getHeaderRulesType(networkACLStr+nacl.Name(), rulesInFilter.RulesFilterType) +
			nacl.analyzer.StringRules(rulesInFilter.Rules)
		if header == "" {
			continue // only dummy rule - nacl not needed between two vsis of the same subnet
		}
		strListRulesInFilter += header
	}
	return strListRulesInFilter
}

func (nl *NaclLayer) StringFilterEffect(listRulesInFilter []vpcmodel.RulesInFilter) string {
	filtersEffectList := []string{}
	for _, rulesInFilter := range listRulesInFilter {
		nacl := nl.naclList[rulesInFilter.Filter]
		header := getSummaryFilterEffect(networkACLStr+nacl.Name(), rulesInFilter.RulesFilterType)
		if header == "" {
			continue // only dummy rule - nacl not needed between two vsis of the same subnet
		}
		filtersEffectList = append(filtersEffectList, header)
	}
	return strings.Join(filtersEffectList, semicolonSeparator)
}

func (nl *NaclLayer) ReferencedIPblocks() []*common.IPBlock {
	res := []*common.IPBlock{}
	for _, n := range nl.naclList {
		res = append(res, n.analyzer.referencedIPblocks...)
	}
	return res
}

func getHeaderRulesType(filter string, rType vpcmodel.RulesType) string {
	switch rType {
	case vpcmodel.NoRules:
		return filter + " blocks connection since there are no relevant allow rules\n"
	case vpcmodel.OnlyDeny:
		return filter + " blocks connection with the following deny rules:\n"
	case vpcmodel.BothAllowDeny:
		return filter + " allows connection with the following allow and deny rules\n"
	case vpcmodel.OnlyAllow:
		return filter + " allows connection with the following allow rules\n"
	default:
		return "" // OnlyDummyRule
	}
}

func getSummaryFilterEffect(filter string, rType vpcmodel.RulesType) string {
	switch rType {
	case vpcmodel.NoRules:
		return filter + " blocks connection (no relevant allow rules)"
	case vpcmodel.OnlyDeny:
		return filter + " blocks connection (with deny rules)"
	case vpcmodel.BothAllowDeny:
		return filter + " allows connection (with allow and deny rules)"
	case vpcmodel.OnlyAllow:
		return filter + " allows connection (with allow rules)"
	default:
		return "" // OnlyDummyRule
	}
}

type NACL struct {
	vpcmodel.VPCResource
	subnets  map[string]*Subnet // map of subnets (pair of cidr strings and subnet obj) for which this nacl is applied to
	analyzer *NACLAnalyzer
}

func (n *NACL) GeneralConnectivityPerSubnet(subnet *Subnet) string {
	res, _ := n.analyzer.GeneralConnectivityPerSubnet(subnet)
	return res
}

func getNodeCidrs(n vpcmodel.Node) (subnetCidr, nodeCidr string, subnet *Subnet, err error) {
	switch t := n.(type) {
	case *NetworkInterface:
		return t.subnet.cidr, t.CidrOrAddress(), t.subnet, nil
	case *IKSNode:
		return t.subnet.cidr, t.CidrOrAddress(), t.subnet, nil
	case *ReservedIP:
		return t.subnet.cidr, t.CidrOrAddress(), t.subnet, nil
	default:
		return "", "", nil, fmt.Errorf("cannot get cidr for node: %+v", n)
	}
}

func (n *NACL) initConnectivityComputation(src, dst vpcmodel.Node,
	isIngress bool) (targetNode vpcmodel.Node, subnetCidr, inSubnetCidr string, subnet *Subnet, err error) {
	if isIngress {
		targetNode = src
		subnetCidr, inSubnetCidr, subnet, err = getNodeCidrs(dst)
	} else {
		targetNode = dst
		subnetCidr, inSubnetCidr, subnet, err = getNodeCidrs(src)
	}
	return targetNode, subnetCidr, inSubnetCidr, subnet, err
}

func (n *NACL) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) (*common.ConnectionSet, error) {
	targetNode, subnetCidr, inSubnetCidr, subnet, err := n.initConnectivityComputation(src, dst, isIngress)
	if err != nil {
		return nil, err
	}
	// check if the subnet of the given node is affected by this nacl
	if _, ok := n.subnets[subnetCidr]; !ok {
		return vpcmodel.NoConns(), nil // not affected by current nacl
	}
	// TODO: differentiate between "has no effect" vs "affects with allow-all / allow-none "
	if targetNode.IPBlock().ContainedIn(subnet.ipblock) {
		return vpcmodel.AllConns(), nil // nacl has no control on traffic between two instances in its subnet
	}
	return n.analyzer.AllowedConnectivity(subnet, inSubnetCidr, targetNode.CidrOrAddress(), isIngress)
}

func (n *NACL) rulesFilterInConnectivity(src, dst vpcmodel.Node, conn *common.ConnectionSet,
	isIngress bool) (tableRelevant bool, allow, deny []int, err error) {
	targetNode, subnetCidr, inSubnetCidr, subnet, err1 := n.initConnectivityComputation(src, dst, isIngress)
	if err1 != nil {
		return false, nil, nil, err1
	}
	// check if the subnet of the given node is affected by this nacl
	if _, ok := n.subnets[subnetCidr]; !ok {
		return false, nil, nil, nil // not affected by current nacl
	}
	// nacl has no control on traffic between two instances in its subnet;
	// this is marked by a rule with index -1 (ibmvpc.DummyRule)
	// which is not printed but only signals that this filter does not block (since there are rules)
	if allInSubnet, err1 := common.IsAddressInSubnet(targetNode.CidrOrAddress(), subnetCidr); err1 == nil && allInSubnet {
		return true, []int{vpcmodel.DummyRule}, nil, nil
	}
	var err2 error
	allow, deny, err2 = n.analyzer.rulesFilterInConnectivity(subnet, subnetCidr, inSubnetCidr, targetNode.CidrOrAddress(), conn, isIngress)
	return true, allow, deny, err2
}

// SecurityGroupLayer captures all SG in the vpc config, analyzes connectivity considering all SG resources
type SecurityGroupLayer struct {
	vpcmodel.VPCResource
	sgList []*SecurityGroup
}

func (sgl *SecurityGroupLayer) Name() string {
	return ""
}

func (sgl *SecurityGroupLayer) ConnectivityMap() (map[string]*vpcmodel.IPbasedConnectivityResult, error) {
	return nil, nil
}

func (sgl *SecurityGroupLayer) GetConnectivityOutputPerEachElemSeparately() string {
	return ""
}

func connHasIKSNode(src, dst vpcmodel.Node, isIngress bool) bool {
	return (isIngress && dst.Kind() == ResourceTypeIKSNode) || (!isIngress && src.Kind() == ResourceTypeIKSNode)
}

// AllowedConnectivity
// TODO: fix: is it possible that no sg applies  to the input peer? if so, should not return "no conns" when none applies
func (sgl *SecurityGroupLayer) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) (*common.ConnectionSet, error) {
	if connHasIKSNode(src, dst, isIngress) {
		return vpcmodel.AllConns(), nil
	}
	res := vpcmodel.NoConns()
	for _, sg := range sgl.sgList {
		sgConn := sg.AllowedConnectivity(src, dst, isIngress)
		res = res.Union(sgConn)
	}
	return res, nil
}

// RulesInConnectivity return allow rules between src and dst,
// or between src and dst of connection conn if conn specified
// denyRules not relevant here - returns nil
func (sgl *SecurityGroupLayer) RulesInConnectivity(src, dst vpcmodel.Node,
	conn *common.ConnectionSet, isIngress bool) (allowRes []vpcmodel.RulesInFilter,
	denyRes []vpcmodel.RulesInFilter, err error) {
	if connHasIKSNode(src, dst, isIngress) {
		return nil, nil, fmt.Errorf("explainability for IKS node not supported yet")
	}
	for index, sg := range sgl.sgList {
		tableRelevant, sgRules, err1 := sg.rulesFilterInConnectivity(src, dst, conn, isIngress)
		if err1 != nil {
			return nil, nil, err1
		}
		if tableRelevant {
			var rType vpcmodel.RulesType = vpcmodel.OnlyAllow
			if len(sgRules) == 0 {
				rType = vpcmodel.NoRules
			}
			rulesInSg := vpcmodel.RulesInFilter{
				Filter:          index,
				Rules:           sgRules,
				RulesFilterType: rType,
			}
			allowRes = append(allowRes, rulesInSg)
		}
	}
	return allowRes, nil, nil
}

func (sgl *SecurityGroupLayer) StringDetailsRulesOfFilter(listRulesInFilter []vpcmodel.RulesInFilter) string {
	strListRulesInFilter := ""
	for _, rulesInFilter := range listRulesInFilter {
		sg := sgl.sgList[rulesInFilter.Filter]
		strListRulesInFilter += getHeaderRulesType(securityGroupStr+sg.Name(), rulesInFilter.RulesFilterType) +
			sg.analyzer.StringRules(rulesInFilter.Rules)
	}
	return strListRulesInFilter
}

func (sgl *SecurityGroupLayer) StringFilterEffect(listRulesInFilter []vpcmodel.RulesInFilter) string {
	filtersEffectList := []string{}
	for _, rulesInFilter := range listRulesInFilter {
		sg := sgl.sgList[rulesInFilter.Filter]
		filtersEffectList = append(filtersEffectList, getSummaryFilterEffect(securityGroupStr+sg.Name(), rulesInFilter.RulesFilterType))
	}
	return strings.Join(filtersEffectList, semicolonSeparator)
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
	members  map[string]vpcmodel.Node // map of members: pairs(address[string], object[NetworkInterface/ReservedIP])
}

func (sg *SecurityGroup) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *common.ConnectionSet {
	memberStrAddress, targetIPBlock := sg.getMemberTargetStrAddress(src, dst, isIngress)
	if _, ok := sg.members[memberStrAddress]; !ok {
		return vpcmodel.NoConns() // connectivity not affected by this SG resource - input node is not its member
	}
	return sg.analyzer.AllowedConnectivity(targetIPBlock, isIngress)
}

// rulesFilterInConnectivity list of SG rules contributing to the connectivity
func (sg *SecurityGroup) rulesFilterInConnectivity(src, dst vpcmodel.Node, conn *common.ConnectionSet,
	isIngress bool) (tableRelevant bool, rules []int, err error) {
	memberStrAddress, targetIPBlock := sg.getMemberTargetStrAddress(src, dst, isIngress)
	if _, ok := sg.members[memberStrAddress]; !ok {
		return false, nil, nil // connectivity not affected by this SG resource - input node is not its member
	}
	rules, err = sg.analyzer.rulesFilterInConnectivity(targetIPBlock, conn, isIngress)
	return true, rules, err
}

func (sg *SecurityGroup) getMemberTargetStrAddress(src, dst vpcmodel.Node,
	isIngress bool) (memberStrAddress string, targetIPBlock *common.IPBlock) {
	var member, target vpcmodel.Node
	if isIngress {
		member = dst
		target = src
	} else {
		member = src
		target = dst
	}
	memberStrAddress = member.CidrOrAddress()
	return memberStrAddress, target.IPBlock()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

// routing resource elements

type FloatingIP struct {
	vpcmodel.VPCResource
	cidr         string
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
}

func (fip *FloatingIP) Sources() []vpcmodel.Node {
	return fip.src
}
func (fip *FloatingIP) Destinations() []vpcmodel.Node {
	return fip.destinations
}

func (fip *FloatingIP) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*common.ConnectionSet, error) {
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(fip.Sources(), src1) && dst1.IsExternal() {
			return vpcmodel.AllConns(), nil
		}
		if vpcmodel.HasNode(fip.Sources(), dst1) && src1.IsExternal() {
			return vpcmodel.AllConns(), nil
		}
		return vpcmodel.NoConns(), nil
	}
	return nil, errors.New("FloatingIP.AllowedConnectivity unexpected src/dst types")
}

func (fip *FloatingIP) AppliedFiltersKinds() map[string]bool {
	return map[string]bool{vpcmodel.SecurityGroupLayer: true}
}

type PublicGateway struct {
	vpcmodel.VPCResource
	cidr         string
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
	srcSubnets   []*Subnet
	subnetCidr   []string
	vpc          *VPC
}

func (pgw *PublicGateway) Zone() (*Zone, error) {
	return pgw.vpc.getZoneByName(pgw.ZoneName())
}

func (pgw *PublicGateway) Sources() []vpcmodel.Node {
	return pgw.src
}
func (pgw *PublicGateway) Destinations() []vpcmodel.Node {
	return pgw.destinations
}

func (pgw *PublicGateway) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*common.ConnectionSet, error) {
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(pgw.Sources(), src1) && dst1.IsExternal() {
			return vpcmodel.AllConns(), nil
		}
		return vpcmodel.NoConns(), nil
	}
	if src.Kind() == ResourceTypeSubnet {
		srcSubnet := src.(*Subnet)
		if dstNode, ok := dst.(vpcmodel.Node); ok {
			if dstNode.IsExternal() && hasSubnet(pgw.srcSubnets, srcSubnet) {
				return vpcmodel.AllConns(), nil
			}
			return vpcmodel.NoConns(), nil
		}
	}
	return nil, errors.New("unexpected src/dst input types")
}

func (pgw *PublicGateway) AppliedFiltersKinds() map[string]bool {
	return map[string]bool{vpcmodel.NaclLayer: true, vpcmodel.SecurityGroupLayer: true}
}

type TransitGateway struct {
	vpcmodel.VPCResource

	// vpcs are the VPCs connected by a TGW
	vpcs []*VPC

	// availableRoutes are the published address prefixes from all connected vpcs that arrive at the TGW's table of available routes,
	// as considered from prefix filters: map from vpc UID to its available routes in the routes table
	availableRoutes map[string][]*common.IPBlock

	// sourceSubnets are the subnets from the connected vpcs that can have connection to destination
	// subnet from another vpc
	sourceSubnets []*Subnet

	// destSubnets are the subnets from the connected vpcs that can de destination for a connection from
	// remote source subnet from another vpc, based on the availableRoutes in the TGW
	destSubnets []*Subnet

	sourceNodes []vpcmodel.Node
	destNodes   []vpcmodel.Node
}

func (tgw *TransitGateway) addSourceAndDestNodes() {
	for _, subnet := range tgw.sourceSubnets {
		tgw.sourceNodes = append(tgw.sourceNodes, subnet.Nodes()...)
	}
	for _, subnet := range tgw.destSubnets {
		tgw.destNodes = append(tgw.destNodes, subnet.Nodes()...)
	}
}

func (tgw *TransitGateway) Sources() (res []vpcmodel.Node) {
	return tgw.sourceNodes
}
func (tgw *TransitGateway) Destinations() (res []vpcmodel.Node) {
	return tgw.destNodes
}

func (tgw *TransitGateway) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*common.ConnectionSet, error) {
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(tgw.sourceNodes, src1) && vpcmodel.HasNode(tgw.destNodes, dst1) {
			return vpcmodel.AllConns(), nil
		}
		return vpcmodel.NoConns(), nil
	}
	if areSubnets, src1, dst1 := isSubnetsPair(src, dst); areSubnets {
		if hasSubnet(tgw.sourceSubnets, src1) && hasSubnet(tgw.destSubnets, dst1) {
			return vpcmodel.AllConns(), nil
		}
		return vpcmodel.NoConns(), nil
	}

	return nil, errors.New("TransitGateway.AllowedConnectivity() expected src and dst to be two nodes or two subnets")
}

// todo: currently not used
func (tgw *TransitGateway) AppliedFiltersKinds() map[string]bool {
	return map[string]bool{vpcmodel.NaclLayer: true, vpcmodel.SecurityGroupLayer: true}
}

func isNodesPair(src, dst vpcmodel.VPCResourceIntf) (res bool, srcNode, dstNode vpcmodel.Node) {
	srcNode, isSrcNode := src.(vpcmodel.Node)
	dstNode, isDstNode := dst.(vpcmodel.Node)
	return isSrcNode && isDstNode, srcNode, dstNode
}

func isSubnetsPair(src, dst vpcmodel.VPCResourceIntf) (res bool, srcSubnet, dstSubnet *Subnet) {
	srcSubnet, isSrcNode := src.(*Subnet)
	dstSubnet, isDstNode := dst.(*Subnet)
	return isSrcNode && isDstNode, srcSubnet, dstSubnet
}

func hasSubnet(listSubnets []*Subnet, subnet *Subnet) bool {
	for _, n := range listSubnets {
		if n.UID() == subnet.UID() {
			return true
		}
	}
	return false
}
