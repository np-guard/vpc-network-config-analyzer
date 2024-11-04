/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ibmvpc

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/np-guard/cloud-resource-collector/pkg/ibm/datamodel"
	"github.com/np-guard/models/pkg/netset"
	"github.com/np-guard/models/pkg/spec"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/commonvpc"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/logging"
	"github.com/np-guard/vpc-network-config-analyzer/pkg/vpcmodel"
)

const doubleTab = "\t\t"

///////////////////////////////////////////////////////////////////////////////////////////////////

func nameWithBracketsInfo(name, inBrackets string) string {
	return fmt.Sprintf("%s[%s]", name, inBrackets)
}

// ReservedIP implements vpcmodel.Node interface
type ReservedIP struct {
	vpcmodel.VPCResource
	vpcmodel.InternalNode
	vpe string
}

func (r *ReservedIP) NameForAnalyzerOut(c *vpcmodel.VPCConfig) string {
	return commonvpc.MultipleVPCsConfigPrefix(c, &r.VPCResource) + nameWithBracketsInfo(r.vpe, r.Address())
}

// used for synthesis output
func (r *ReservedIP) SynthesisResourceName() string {
	return r.VPC().Name() + vpcmodel.Deliminator + r.vpe
}

func (r *ReservedIP) SynthesisKind() spec.ResourceType {
	return spec.ResourceTypeVpe
}

// PrivateIP implements vpcmodel.Node interface
type PrivateIP struct {
	vpcmodel.VPCResource
	vpcmodel.InternalNode
	loadBalancer *LoadBalancer
	// Since not all the LB has a private IP, we create a potential Private IP at the LB's subnets that do not have one.
	// original - does the private IP was originally at the config file, or is it a potential one
	original bool
	// the potential block which the pip was created for:
	block *netset.IPBlock
}

func (pip *PrivateIP) NameForAnalyzerOut(c *vpcmodel.VPCConfig) string {
	kind := "LB private IP"
	address := pip.Address()
	if !pip.original {
		kind = "Potential " + kind
		// todo - use ToRangesListString() instead of ListToPrint()
		address = strings.Join(pip.block.ListToPrint(), ",")
	}
	name := nameWithBracketsInfo(pip.loadBalancer.Name(), kind)
	return commonvpc.MultipleVPCsConfigPrefix(c, &pip.VPCResource) + nameWithBracketsInfo(name, address)
}

// AbstractedToNodeSet returns the pip load balancer if it was abstracted
func (pip *PrivateIP) AbstractedToNodeSet() vpcmodel.NodeSet {
	if pip.loadBalancer.AbstractionInfo() != nil {
		return pip.loadBalancer
	}
	return nil
}
func (pip *PrivateIP) RepresentedByAddress() bool {
	return false
}

// IKSNode implements vpcmodel.Node interface
type IKSNode struct {
	vpcmodel.VPCResource
	vpcmodel.InternalNode
}

func (n *IKSNode) VsiName() string {
	return ""
}

func (n *IKSNode) NameForAnalyzerOut(c *vpcmodel.VPCConfig) string {
	return commonvpc.MultipleVPCsConfigPrefix(c, &n.VPCResource) + nameWithBracketsInfo(n.Name(), n.Address())
}

// vpe can be in multiple zones - depending on the zones of its network interfaces..
type Vpe struct {
	vpcmodel.VPCResource
	nodes []vpcmodel.Node
}

func (v *Vpe) Nodes() []vpcmodel.Node {
	return v.nodes
}

func (v *Vpe) AddressRange() *netset.IPBlock {
	return nodesAddressRange(v.nodes)
}

// vpe is per vpc and not per zone...
func (v *Vpe) Zone() (*commonvpc.Zone, error) {
	return nil, nil
}

func nodesAddressRange(nodes []vpcmodel.Node) *netset.IPBlock {
	var res *netset.IPBlock
	for _, n := range nodes {
		if res == nil {
			res = n.IPBlock()
		} else {
			res = res.Union(n.IPBlock())
		}
	}
	return res
}

// LoadBalancerPool //////////////////////////////////////////
// Load Balancer
// the nodes are the private IPs
// the listeners hold the pools that holds the backend servers (aka pool members)
type LoadBalancerPool []vpcmodel.Node
type LoadBalancerListener []LoadBalancerPool

type LoadBalancer struct {
	vpcmodel.VPCResource
	nodes     []vpcmodel.Node
	listeners []LoadBalancerListener
	// abstractionInfo holds the information the relevant for the abstraction of the load balancer
	abstractionInfo *vpcmodel.AbstractionInfo
}

// for LB we add the kind to the name, to make it clear in the reports
func (lb *LoadBalancer) nameWithKind() string {
	return nameWithBracketsInfo(lb.ResourceName, lb.Kind())
}
func (lb *LoadBalancer) NameForAnalyzerOut(c *vpcmodel.VPCConfig) string {
	return commonvpc.MultipleVPCsConfigPrefix(c, &lb.VPCResource) + lb.nameWithKind()
}

func (lb *LoadBalancer) Nodes() []vpcmodel.Node {
	return lb.nodes
}
func (lb *LoadBalancer) AddressRange() *netset.IPBlock {
	return nodesAddressRange(lb.nodes)
}

func (lb *LoadBalancer) GetLoadBalancerRule(src, dst vpcmodel.Node) vpcmodel.LoadBalancerRule {
	// currently, we do not allow connections from privateIP to a destination that is not a pool member
	if slices.Contains(lb.Nodes(), src) {
		if !slices.Contains(lb.members(), dst) {
			return NewLoadBalancerRule(lb, true, src, dst)
		}
		return NewLoadBalancerRule(lb, false, src, dst)
	}
	return nil
}

// for now the listeners hold the pools that holds the backend servers (aka pool members)
func (lb *LoadBalancer) members() []vpcmodel.Node {
	res := []vpcmodel.Node{}
	for _, l := range lb.listeners {
		for _, pool := range l {
			res = append(res, pool...)
		}
	}
	return res
}

// lb is per vpc and not per zone...
func (lb *LoadBalancer) Zone() (*commonvpc.Zone, error) {
	return nil, nil
}

func (lb *LoadBalancer) SetAbstractionInfo(abstractionInfo *vpcmodel.AbstractionInfo) {
	lb.abstractionInfo = abstractionInfo
}
func (lb *LoadBalancer) AbstractionInfo() *vpcmodel.AbstractionInfo {
	return lb.abstractionInfo
}

// ////////////////////////////////////////////////////////////////////////////////
// LoadBalancerRule is a rule applied to all private IPs of a given load balancer:
// these private IPs can only init connection to pool members of the load balancer.
type LoadBalancerRule struct {
	// the relevant load balancer:
	lb *LoadBalancer
	//	deny- true if src is pip, and dst is not pool member:
	deny     bool
	src, dst vpcmodel.Node
}

func NewLoadBalancerRule(lb *LoadBalancer, deny bool, src, dst vpcmodel.Node) vpcmodel.LoadBalancerRule {
	return &LoadBalancerRule{lb, deny, src, dst}
}

func (lbr *LoadBalancerRule) Deny(isIngress bool) bool { return !isIngress && lbr.deny }

// IsIngress load balancer potentially blocks egress connection
func (lbr *LoadBalancerRule) IsIngress() bool {
	return false
}

// todo: use detail to get a concise printing for !detail
func (lbr *LoadBalancerRule) String(detail bool) string {
	if lbr.Deny(false) {
		return fmt.Sprintf("%s will not connect to %s, since it is not its pool member\n",
			lbr.lb.nameWithKind(), lbr.dst.NameForAnalyzerOut(nil))
	}
	return fmt.Sprintf("%s may initiate a connection to %s, which is one of its pool members\n",
		lbr.lb.nameWithKind(), lbr.dst.NameForAnalyzerOut(nil))
}

// routing resource elements

type FloatingIP struct {
	vpcmodel.VPCResource
	cidr         string // todo: this is actually not cidr but external IP. Rename?
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
}

func (fip *FloatingIP) Sources() []vpcmodel.Node {
	return fip.src
}
func (fip *FloatingIP) SourcesSubnets() []vpcmodel.Subnet {
	return nil
}

func (fip *FloatingIP) Destinations() []vpcmodel.Node {
	return fip.destinations
}
func (fip *FloatingIP) SetExternalDestinations(destinations []vpcmodel.Node) {
	fip.destinations = destinations
}

func (fip *FloatingIP) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*netset.TransportSet, error) {
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(fip.Sources(), src1) && dst1.IsExternal() {
			return netset.AllTransports(), nil
		}
		if vpcmodel.HasNode(fip.Sources(), dst1) && src1.IsExternal() {
			return netset.AllTransports(), nil
		}
		return netset.NoTransports(), nil
	}
	return nil, errors.New("FloatingIP.AllowedConnectivity unexpected src/dst types")
}

func (fip *FloatingIP) RouterDefined(src, dst vpcmodel.Node) bool {
	return (vpcmodel.HasNode(fip.Sources(), src) && dst.IsExternal()) ||
		(vpcmodel.HasNode(fip.Sources(), dst) && src.IsExternal())
}

func (fip *FloatingIP) ExternalIP() string {
	return fip.cidr
}

func (fip *FloatingIP) RulesInConnectivity(src, dst vpcmodel.Node) []vpcmodel.RulesInTable {
	return nil
}

func (fip *FloatingIP) StringOfRouterRules(listRulesInFilter []vpcmodel.RulesInTable,
	verbose bool) (string, error) {
	return "", nil
}

func (fip *FloatingIP) IsMultipleVPCs() bool {
	return false
}

// ServiceNetworkGateway is a virtual gateway
// we add it for convenience - it is not a resource that appears in the input configuration file.
type ServiceNetworkGateway struct {
	vpcmodel.VPCResource
	cidr *ipblock.IPBlock
}

func (sgw *ServiceNetworkGateway) Cidr() *ipblock.IPBlock {
	return sgw.cidr
}
func (sgw *ServiceNetworkGateway) Sources() []vpcmodel.Node {
	return nil
}
func (sgw *ServiceNetworkGateway) SourcesSubnets() []vpcmodel.Subnet {
	return nil
}

func (sgw *ServiceNetworkGateway) Destinations() []vpcmodel.Node {
	return nil
}
func (sgw *ServiceNetworkGateway) SetExternalDestinations(destinations []vpcmodel.Node) {
}

func (sgw *ServiceNetworkGateway) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*connection.Set, error) {
	if areNodes, _, dst1 := isNodesPair(src, dst); areNodes {
		if dst1.IsExternal() && !dst1.IsPublicInternet() {
			return connection.All(), nil
		}
		return connection.None(), nil
	}
	return nil, errors.New("ServiceNetworkGateway.AllowedConnectivity unexpected src/dst types")
}

func (sgw *ServiceNetworkGateway) RouterDefined(src, dst vpcmodel.Node) bool {
	return dst.IsExternal() && !dst.IsPublicInternet()
}

func (sgw *ServiceNetworkGateway) ExternalIP() string {
	return ""
}

func (sgw *ServiceNetworkGateway) RulesInConnectivity(src, dst vpcmodel.Node) []vpcmodel.RulesInTable {
	return nil
}

func (sgw *ServiceNetworkGateway) StringOfRouterRules(listRulesInFilter []vpcmodel.RulesInTable,
	verbose bool) (string, error) {
	return "", nil
}

func (sgw *ServiceNetworkGateway) IsMultipleVPCs() bool {
	return false
}

type PublicGateway struct {
	vpcmodel.VPCResource
	cidr         string
	src          []vpcmodel.Node
	destinations []vpcmodel.Node
	// todo - the following should be []vpcmodel.Subnet, however, I can not do this fix now, since it involve a big fix in the parser.
	// and the parser has 2 PRs on it. will fix with issue #740
	srcSubnets []*commonvpc.Subnet
	subnetCidr []string
	vpc        *commonvpc.VPC
}

func (pgw *PublicGateway) Zone() (*commonvpc.Zone, error) {
	return pgw.vpc.GetZoneByName(pgw.ZoneName())
}

func (pgw *PublicGateway) Sources() []vpcmodel.Node {
	return pgw.src
}
func (pgw *PublicGateway) SourcesSubnets() []vpcmodel.Subnet {
	// todo - rewrite with issue #740
	res := make([]vpcmodel.Subnet, len(pgw.srcSubnets))
	for i, s := range pgw.srcSubnets {
		res[i] = s
	}
	return res
}

func (pgw *PublicGateway) Destinations() []vpcmodel.Node {
	return pgw.destinations
}
func (pgw *PublicGateway) SetExternalDestinations(destinations []vpcmodel.Node) {
	pgw.destinations = destinations
}

func (pgw *PublicGateway) ExternalIP() string {
	return ""
}

func (pgw *PublicGateway) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*netset.TransportSet, error) {
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(pgw.Sources(), src1) && dst1.IsExternal() && dst1.IsPublicInternet() {
			return netset.AllTransports(), nil
		}
		return netset.NoTransports(), nil
	}
	if src.Kind() == commonvpc.ResourceTypeSubnet {
		srcSubnet := src.(*commonvpc.Subnet)
		if dstNode, ok := dst.(vpcmodel.Node); ok {
			if dstNode.IsExternal() && dstNode.IsPublicInternet() && hasSubnet(pgw.srcSubnets, srcSubnet) {
				netset.AllTransports(), nil
			}
			return netset.NoTransports(), nil
		}
	}
	return nil, errors.New("unexpected src/dst input types")
}

func (pgw *PublicGateway) RouterDefined(src, dst vpcmodel.Node) bool {
	return vpcmodel.HasNode(pgw.Sources(), src) && dst.IsExternal() && dst.IsPublicInternet()
}

func (pgw *PublicGateway) RulesInConnectivity(src, dst vpcmodel.Node) []vpcmodel.RulesInTable {
	return nil
}

func (pgw *PublicGateway) StringOfRouterRules(listRulesInFilter []vpcmodel.RulesInTable,
	verbose bool) (string, error) {
	return "", nil
}

func (pgw *PublicGateway) IsMultipleVPCs() bool {
	return false
}

type TransitGateway struct {
	vpcmodel.VPCResource

	// vpcs are the VPCs connected by a TGW
	vpcs []*commonvpc.VPC

	// list of all transit connections (not only those relevant to this TransitGateway)
	tgwConnList []*datamodel.TransitConnection

	// availableRoutes are the published address prefixes from all connected vpcs that arrive at the TGW's table of available routes,
	// as considered from prefix filters: map from vpc UID to its available routes in the routes table
	availableRoutes map[string][]*netset.IPBlock

	// sourceSubnets are the subnets from the connected vpcs that can have connection to destination
	// subnet from another vpc
	sourceSubnets []*commonvpc.Subnet

	// destSubnets are the subnets from the connected vpcs that can de destination for a connection from
	// remote source subnet from another vpc, based on the availableRoutes in the TGW
	destSubnets []*commonvpc.Subnet

	sourceNodes []vpcmodel.Node
	destNodes   []vpcmodel.Node

	region *commonvpc.Region

	// maps each VPC UID to the details of the matching filters
	// these details includes map of each relevant IPBlock to the transit connection (its index in the tgwConnList)
	// and the index of the matching filter in the transit connection if exists (index "-1" is for default )
	// this struct can be though of as the "explain" parallel of availableRoutes; note that unlike availableRoutes it also lists deny prefixes
	vpcsAPToPrefixRules map[string]map[*netset.IPBlock]vpcmodel.RulesInTable
}

func (tgw *TransitGateway) addSourceAndDestNodes() {
	for _, subnet := range tgw.sourceSubnets {
		tgw.sourceNodes = append(tgw.sourceNodes, subnet.Nodes()...)
	}
	for _, subnet := range tgw.destSubnets {
		tgw.destNodes = append(tgw.destNodes, subnet.Nodes()...)
	}
}

func (tgw *TransitGateway) Region() *commonvpc.Region {
	return tgw.region
}

func (tgw *TransitGateway) Sources() (res []vpcmodel.Node) {
	return tgw.sourceNodes
}
func (tgw *TransitGateway) Destinations() (res []vpcmodel.Node) {
	return tgw.destNodes
}
func (tgw *TransitGateway) SourcesSubnets() []vpcmodel.Subnet {
	// todo - rewrite with fix of issue #740
	res := make([]vpcmodel.Subnet, len(tgw.sourceSubnets))
	for i, s := range tgw.sourceSubnets {
		res[i] = s
	}
	return res
}

func (tgw *TransitGateway) SetExternalDestinations(destinations []vpcmodel.Node) {
}

func (tgw *TransitGateway) ExternalIP() string {
	return ""
}

func isPairRelevantToTGW(src, dst vpcmodel.VPCResourceIntf) bool {
	return !(src.IsExternal() || dst.IsExternal()) && src.VPC().UID() != dst.VPC().UID()
}

func (tgw *TransitGateway) AllowedConnectivity(src, dst vpcmodel.VPCResourceIntf) (*netset.TransportSet, error) {
	if !isPairRelevantToTGW(src, dst) {
		logging.Debugf("pair not relevant to TGW")
		return netset.NoTransports(), nil
	}
	if areNodes, src1, dst1 := isNodesPair(src, dst); areNodes {
		if vpcmodel.HasNode(tgw.sourceNodes, src1) && vpcmodel.HasNode(tgw.destNodes, dst1) {
			logging.Debugf("tgw enables this connectivity")
			return netset.AllTransports(), nil
		}
		logging.Debugf("tgw disables this connectivity")
		return netset.NoTransports(), nil
	}
	if areSubnets, src1, dst1 := isSubnetsPair(src, dst); areSubnets {
		if hasSubnet(tgw.sourceSubnets, src1) && hasSubnet(tgw.destSubnets, dst1) {
			return netset.AllTransports(), nil
		}
		return netset.NoTransports(), nil
	}

	logging.Debugf("err")
	return nil, errors.New("TransitGateway.AllowedConnectivity() expected src and dst to be two nodes or two subnets")
}

func (tgw *TransitGateway) RouterDefined(src, dst vpcmodel.Node) bool {
	if !isPairRelevantToTGW(src, dst) {
		return false
	}

	// if both src and dst nodes are within tgw.sourceNodes, it means that they are both within VPCs attached to this TGW
	// note that tgw.destNodes does not necessarily contain all these nodes, due to prefix filters
	return vpcmodel.HasNode(tgw.sourceNodes, src) && vpcmodel.HasNode(tgw.sourceNodes, dst)
}

// gets a string description of prefix indexed "index" from TransitGateway tgw
//
//nolint:gocritic // no need to name return values. too short
func prefixDefaultStr(tc *datamodel.TransitConnection) (string, string, error) {
	actionName, err := actionNameStr(tc.PrefixFiltersDefault)
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("default prefix,  action: %s", actionName), actionName, nil
}

func (tgw *TransitGateway) tgwPrefixStr(tc *datamodel.TransitConnection,
	prefixIndx int) (resStr, actionName string, err error) {
	// Array of prefix route filters for a transit gateway connection. This is order dependent with those first in the
	// array being applied first, and those at the end of the array is applied last, or just before the default.
	if prefixIndx == defaultPrefixFilter { // default
		defaultStr, actionName, err := prefixDefaultStr(tc)
		if err != nil {
			return "", "", err
		}
		return resStr + defaultStr, actionName, nil
	}
	if len(tc.PrefixFilters) < prefixIndx+1 {
		return "", "", fmt.Errorf("np-guard error: prefix index %d does not exists in transit connection %s of transit gateway %s",
			prefixIndx, *tc.Name, tgw.Name())
	}
	prefixFilter := tc.PrefixFilters[prefixIndx]
	actionName, err = actionNameStr(prefixFilter.Action)
	if err != nil {
		return "", "", err
	}
	resStr += fmt.Sprintf("index: %v, action: %s", prefixIndx, actionName)
	if prefixFilter.Ge != nil {
		resStr += fmt.Sprintf(", ge: %v", *prefixFilter.Ge)
	}
	if prefixFilter.Le != nil {
		resStr += fmt.Sprintf(", le: %v", *prefixFilter.Le)
	}
	resStr += fmt.Sprintf(", prefix: %s", *prefixFilter.Prefix)
	return resStr, actionName, nil
}

// for an action of type *string as stored in *datamodel.TransitConnection returns allow/deny
func actionNameStr(action *string) (string, error) {
	actionBool, err := parseActionString(action)
	if err != nil {
		return "", err
	}
	if actionBool {
		return permitAction, nil
	}
	return denyAction, nil
}

// RulesInConnectivity returns the prefix filters relevant for <src, dst>.
// src/dst could be a cidr, so for a single <src,dst> query there could be more than one relevant prefix filter
// (in a single transit connection)
// However, each src/dst maps to a set of endpoints (Nodes) and the query is for the Cartesian product of these.
// Specifically, this functionality is between <src, dst> where each is a single endpoint (single IP addr)
// and prefix filter rules do not include protocol or ports (unlike nacls and sgs)
// Thus, for each such <src, dst> there is a single prefix filter
func (tgw *TransitGateway) RulesInConnectivity(src, dst vpcmodel.Node) []vpcmodel.RulesInTable {
	// <src, dst> routed by tgw given that source is in the tgw, and there is a prefix filter defined for the dst,
	// the relevant prefix filter is determined by match of the Address prefix the dest's node is in (including default)
	// Note, again, that for each (src, dst vpcmodel.Node) there is a single prefix filter
	if vpcmodel.HasNode(tgw.sourceNodes, src) {
		for ipBlock, transitConnectionPrefixes := range tgw.vpcsAPToPrefixRules[dst.VPC().UID()] {
			if dst.IPBlock().Overlap(ipBlock) {
				return []vpcmodel.RulesInTable{transitConnectionPrefixes}
			}
		}
	}
	return nil // should never get here
}

func (tgw *TransitGateway) StringOfRouterRules(listRulesInTransitConns []vpcmodel.RulesInTable, verbose bool) (string, error) {
	strRes := []string{}
	for _, prefixesInTransitConn := range listRulesInTransitConns {
		transitConn := tgw.tgwConnList[prefixesInTransitConn.TableIndex]
		if verbose {
			verboseStr, err := tgw.stringPrefixFiltersVerbose(transitConn, prefixesInTransitConn)
			if err != nil {
				return "", err
			}
			strRes = append(strRes, verboseStr...)
		} else {
			strRes = append(strRes, tgw.stringPrefixFiltersNoVerbose(transitConn, prefixesInTransitConn.RulesOfType))
		}
	}
	sort.Strings(strRes)
	return strings.Join(strRes, "\n") + "\n", nil
}

// given a transit connection and a list of the relevant prefix in the connections, prints the relevant prefix details
func (tgw *TransitGateway) stringPrefixFiltersVerbose(transitConn *datamodel.TransitConnection,
	prefixesInTransitConn vpcmodel.RulesInTable) ([]string, error) {
	strRes := []string{}
	for _, prefixInTransConnIndx := range prefixesInTransitConn.Rules {
		thisPrefixStr := ""
		tgwRouterFilterDetails, actionName, err := tgw.tgwPrefixStr(transitConn, prefixInTransConnIndx)
		if err != nil {
			return nil, err
		}
		action := ""
		if actionName == permitAction {
			action = "allows"
		} else {
			action = "blocks"
		}
		thisPrefixStr = fmt.Sprintf("\ttransit gateway %s %s connection via transit connection %s "+
			"with the following prefix filter\n%s%s\n", tgw.Name(), action, *transitConn.Name,
			doubleTab, tgwRouterFilterDetails)
		strRes = append(strRes, thisPrefixStr)
	}
	return strRes, nil
}

// given a transit connection and the effect (onlyDeny/onlyAllow) of this transit gateway on queried <src, dst> ,
// prints a matching non-verbose header
func (tgw *TransitGateway) stringPrefixFiltersNoVerbose(transitConn *datamodel.TransitConnection,
	rulesType vpcmodel.RulesType) string {
	noVerboseStr := fmt.Sprintf("cross-vpc-connection: transit-connection %s of transit-gateway %s ",
		*transitConn.Name, tgw.Name())
	switch rulesType {
	case vpcmodel.OnlyAllow:
		return noVerboseStr + "allows connection"
	case vpcmodel.OnlyDeny:
		return noVerboseStr + "denies connection"
	}
	return "" // should never get here
}

func isNodesPair(src, dst vpcmodel.VPCResourceIntf) (res bool, srcNode, dstNode vpcmodel.Node) {
	srcNode, isSrcNode := src.(vpcmodel.Node)
	dstNode, isDstNode := dst.(vpcmodel.Node)
	return isSrcNode && isDstNode, srcNode, dstNode
}

func isSubnetsPair(src, dst vpcmodel.VPCResourceIntf) (res bool, srcSubnet, dstSubnet *commonvpc.Subnet) {
	srcSubnet, isSrcNode := src.(*commonvpc.Subnet)
	dstSubnet, isDstNode := dst.(*commonvpc.Subnet)
	return isSrcNode && isDstNode, srcSubnet, dstSubnet
}

func hasSubnet(listSubnets []*commonvpc.Subnet, subnet *commonvpc.Subnet) bool {
	for _, n := range listSubnets {
		if n.UID() == subnet.UID() {
			return true
		}
	}
	return false
}
func (tgw *TransitGateway) IsMultipleVPCs() bool {
	return true
}
