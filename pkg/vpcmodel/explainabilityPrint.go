/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/models/pkg/connection"
)

const arrow = " -> "
const newLineTab = "\n\t"
const space = " "
const comma = ", "
const newLine = "\n"
const doubleNL = "\n\n"
const tripleNLVars = "\n\n%s\n%s"
const emptyString = ""

// header of txt/debug format
func explainHeader(explanation *Explanation) string {
	srcNetworkInterfaces := listNetworkInterfaces(explanation.c, explanation.srcNetworkInterfacesFromIP)
	dstNetworkInterfaces := listNetworkInterfaces(explanation.c, explanation.dstNetworkInterfacesFromIP)
	singleVpcContext := ""
	// communication within a single vpc
	if explanation.c != nil && !explanation.c.IsMultipleVPCsConfig {
		singleVpcContext = fmt.Sprintf(" within %v", explanation.c.VPC.Name())
	}
	header1 := fmt.Sprintf("Explaining connectivity from %s%s to %s%s%s%s",
		explanation.src, srcNetworkInterfaces, explanation.dst, dstNetworkInterfaces, singleVpcContext,
		connHeader(explanation.connQuery))
	header2 := strings.Repeat("=", len(header1))
	return header1 + newLine + header2 + doubleNL
}

// used to print 1) the query in the first header
// 2) the actual allowed connection from the queried one in the 2nd header
func connHeader(connQuery *connection.Set) string {
	if connQuery != nil {
		return " using \"" + connQuery.String() + "\""
	}
	return ""
}

// in case the src/dst of a network interface given as an internal address connected to network interface returns a string
// of all relevant nodes names
func listNetworkInterfaces(c *VPCConfig, nodes []Node) string {
	if len(nodes) == 0 {
		return emptyString
	}
	networkInterfaces := make([]string, len(nodes))
	for i, node := range nodes {
		networkInterfaces[i] = node.ExtendedName(c)
	}
	return leftParentheses + strings.Join(networkInterfaces, comma) + rightParentheses
}

// String main printing function for the Explanation struct - returns a string with the explanation
func (explanation *Explanation) String(verbose bool) string {
	if explanation.c == nil { // no VPCConfig - missing cross-VPC router (tgw)
		return explainMissingCrossVpcRouter(explanation.src, explanation.dst, explanation.connQuery)
	}
	linesStr := make([]string, len(explanation.groupedLines))
	groupedLines := explanation.groupedLines
	for i, groupedLine := range groupedLines {
		linesStr[i] += groupedLine.explainabilityLineStr(explanation.c, explanation.connQuery, verbose) +
			"------------------------------------------------------------------------------------------------------------------------\n"
	}
	sort.Strings(linesStr)
	iksNodeComment := ""
	if explanation.hasIksNode {
		iksNodeComment = "* Analysis of the connectivity of cluster worker nodes is under the assumption that the " +
			"only security groups applied to them are the VPC default and the IKS generated SG\n"
	}
	return strings.Join(linesStr, newLine) + newLine + iksNodeComment
}

// missing cross vpc router
// in this case there is no *VPCConfig we can work with, so this case is treated separately
func explainMissingCrossVpcRouter(src, dst string, connQuery *connection.Set) string {
	return fmt.Sprintf("%vAll connections will be blocked since source and destination are in different VPCs with no transit gateway to "+
		"connect them", noConnectionHeader(src, dst, connQuery)+newLine)
}

// prints a single line of explanation for externalAddress grouped <src, dst>
// The printing contains 4 sections:
//  1. Header describing the query and whether there is a connection. E.g.:
//     * Allowed connections from ky-vsi0-subnet5[10.240.9.4] to ky-vsi0-subnet11[10.240.80.4]: All Connections
//     The TCP sub-connection is responsive
//     * No connections are allowed from ky-vsi1-subnet20[10.240.128.5] to ky-vsi0-subnet0[10.240.0.5];
//  2. List of all the different resources effecting the connection and the effect of each. E.g.:
//
// cross-vpc-connection: transit-connection tg_connection0 of transit-gateway local-tg-ky denys connection
// Egress: security group sg21-ky allows connection; network ACL acl21-ky allows connection
// Ingress: network ACL acl1-ky allows connection; security group sg1-ky allows connection
//  3. Connection path description. E.g.:
//     ky-vsi1-subnet20[10.240.128.5] -> security group sg21-ky -> subnet20 -> network ACL acl21-ky ->
//     test-vpc2-ky -> TGW local-tg-ky -> |
//
// 4. Details of enabling and disabling rules/prefixes, including details of each rule
// todo add details of enabling/disabling rules for return path
//
// 1 and 3 are printed always
// 2 is printed only when the connection is blocked. It is redundant when the entire path ("3") is printed. When
// the connection is blocked and only part of the path is printed then 2 is printed so that the relevant information
// is provided regardless of where the is blocking
// 4 is printed only in debug mode
func (g *groupedConnLine) explainabilityLineStr(c *VPCConfig, connQuery *connection.Set, verbose bool) string {
	expDetails := g.commonProperties.expDetails
	filtersRelevant := g.commonProperties.expDetails.filtersRelevant
	src, dst := g.src, g.dst
	needEgress := !src.IsExternal()
	needIngress := !dst.IsExternal()
	ingressBlocking := !expDetails.ingressEnabled && needIngress
	egressBlocking := !expDetails.egressEnabled && needEgress
	var externalRouterHeader, crossRouterFilterHeader, resourceEffectHeader,
		crossRouterFilterDetails, details string
	externalRouter, crossVpcRouter, crossVpcRules := expDetails.externalRouter, expDetails.crossVpcRouter, expDetails.crossVpcRules
	if externalRouter != nil && (src.IsExternal() || dst.IsExternal()) {
		externalRouterHeader = "External traffic via " + externalRouter.Kind() + ": " + externalRouter.Name() + newLine
	}
	var crossVpcConnection *connection.Set
	crossVpcConnection, crossRouterFilterHeader, crossRouterFilterDetails = crossRouterDetails(c, crossVpcRouter, crossVpcRules,
		src, dst)
	// noConnection is the 1 above when no connection
	noConnection := noConnectionHeader(src.ExtendedName(c), dst.ExtendedName(c), connQuery) + newLine

	// resourceEffectHeader is "2" above
	rules := expDetails.rules
	egressRulesHeader, ingressRulesHeader := rules.filterEffectStr(c, filtersRelevant, needEgress, needIngress)
	resourceEffectHeader = externalRouterHeader + egressRulesHeader + crossRouterFilterHeader +
		ingressRulesHeader + newLine

	// path in "3" above
	path := "Path:\n" + pathStr(c, filtersRelevant, src, dst,
		ingressBlocking, egressBlocking, externalRouter, crossVpcRouter, crossVpcConnection, rules) + newLine
	// details is "4" above
	egressRulesDetails, ingressRulesDetails := rules.ruleDetailsStr(c, filtersRelevant, needEgress, needIngress)
	conn := g.commonProperties.conn
	if verbose {
		details = "\nDetails:\n~~~~~~~~\nPath enabled by the following rules:\n" +
			egressRulesDetails + crossRouterFilterDetails + ingressRulesDetails
		if respondRulesRelevant(conn, filtersRelevant) {
			// for respond rules needIngress and needEgress are switched
			respondEgressDetails, respondsIngressDetails := expDetails.respondRules.ruleDetailsStr(c, filtersRelevant, needIngress, needEgress)
			details += conn.respondDetailsHeader() + respondEgressDetails + respondsIngressDetails
		}
	}
	return g.explainPerCaseStr(c, src, dst, connQuery, crossVpcConnection, ingressBlocking, egressBlocking,
		noConnection, resourceEffectHeader, path, details)
}

// assumption: the func is called only if the tcp component of the connection is not empty
func (conn *detailedConn) respondDetailsHeader() string {
	switch {
	case conn.tcpRspDisable.IsEmpty():
		return "TCP respond enabled by the following rules:\n"
	case conn.tcpRspEnable.IsEmpty():
		return "TCP respond disabled by the following rules:\n"
	default:
		return "TCP respond partly enabled by the following rules:\n"
	}
}

// after all data is gathered, generates the actual string to be printed
func (g *groupedConnLine) explainPerCaseStr(c *VPCConfig, src, dst EndpointElem,
	connQuery, crossVpcConnection *connection.Set, ingressBlocking, egressBlocking bool,
	noConnection, resourceEffectHeader, path, details string) string {
	conn := g.commonProperties.conn
	externalRouter, crossVpcRouter := g.commonProperties.expDetails.externalRouter,
		g.commonProperties.expDetails.crossVpcRouter
	headerPlusPath := resourceEffectHeader + path
	switch {
	case crossVpcRouterRequired(src, dst) && crossVpcRouter != nil && crossVpcConnection.IsEmpty():
		return fmt.Sprintf("%vAll connections will be blocked since transit gateway denies route from source to destination"+tripleNLVars,
			noConnection, headerPlusPath, details)
	case externalRouter == nil && src.IsExternal():
		return fmt.Sprintf("%vno fip and src is external (fip is required for "+
			"outbound external connection)\n", noConnection)
	case externalRouter == nil && dst.IsExternal():
		return fmt.Sprintf("%v\tThe dst is external but there is no Floating IP or Public Gateway connecting to public internet\n",
			noConnection)
	case ingressBlocking && egressBlocking:
		return fmt.Sprintf("%vconnection blocked both by ingress and egress"+tripleNLVars, noConnection,
			headerPlusPath, details)
	case ingressBlocking:
		return fmt.Sprintf("%vconnection blocked by ingress"+tripleNLVars, noConnection,
			headerPlusPath, details)
	case egressBlocking:
		return fmt.Sprintf("%vconnection blocked by egress"+tripleNLVars, noConnection,
			headerPlusPath, details)
	default: // there is a connection
		return existingConnectionStr(c, connQuery, src, dst, conn, path, details)
	}
}

func crossRouterDetails(c *VPCConfig, crossVpcRouter RoutingResource, crossVpcRules []RulesInTable,
	src, dst EndpointElem) (crossVpcConnection *connection.Set,
	crossVpcRouterFilterHeader, crossVpcFilterDetails string) {
	if crossVpcRouter != nil {
		// an error here will pop up earlier, when computing connections
		_, crossVpcConnection, _ := c.getRoutingResource(src.(Node), dst.(Node)) // crossVpc Router (tgw) exists - src, dst are internal
		// if there is a non nil transit gateway then src and dst are vsis, and implement Node
		crossVpcFilterHeader, _ := crossVpcRouter.StringDetailsOfRules(crossVpcRules, false)
		crossVpcFilterDetails, _ := crossVpcRouter.StringDetailsOfRules(crossVpcRules, true)
		return crossVpcConnection, crossVpcFilterHeader, crossVpcFilterDetails
	}
	return nil, emptyString, emptyString
}

func crossVpcRouterRequired(src, dst EndpointElem) bool {
	if src.IsExternal() || dst.IsExternal() {
		return false
	}
	// both internal
	return src.(InternalNodeIntf).Subnet().VPC().UID() !=
		dst.(InternalNodeIntf).Subnet().VPC().UID()
}

// returns string of header in case a connection fails to exist
func noConnectionHeader(src, dst string, connQuery *connection.Set) string {
	return fmt.Sprintf("No connections are allowed from %s to %s%s;", src, dst, connHeader(connQuery))
}

// printing when connection exists.
// computing "1" when there is a connection and adding to it already computed "2" and "3" as described in explainabilityLineStr
func existingConnectionStr(c *VPCConfig, connQuery *connection.Set, src, dst EndpointElem,
	conn *detailedConn, path, details string) string {
	resComponents := []string{}
	// Computing the header, "1" described in explainabilityLineStr
	respondConnStr := conn.respondString()
	if connQuery == nil {
		resComponents = append(resComponents, fmt.Sprintf("Allowed connections from %v to %v: %v%v\n", src.ExtendedName(c), dst.ExtendedName(c),
			conn.allConn.String(), respondConnStr))
	} else {
		properSubsetConn := ""
		if !conn.allConn.Equal(connQuery) {
			properSubsetConn = "(note that not all queried protocols/ports are allowed)\n"
		}
		resComponents = append(resComponents, fmt.Sprintf("Connections are allowed from %s to %s%s%s\n%s",
			src.ExtendedName(c), dst.ExtendedName(c), connHeader(conn.allConn), respondConnStr, properSubsetConn))
	}
	resComponents = append(resComponents, path, details)
	return strings.Join(resComponents, newLine)
}

// returns a couple of strings of an egress, ingress summary of each filter (table) effect; e.g.
// "Egress: security group sg1-ky allows connection; network ACL acl1-ky blocks connection
// Ingress: network ACL acl3-ky allows connection; security group sg1-ky allows connection"
func (rules *rulesConnection) filterEffectStr(c *VPCConfig, filtersRelevant map[string]bool, needEgress,
	needIngress bool) (egressRulesHeader, ingressRulesHeader string) {
	if needEgress {
		egressRulesHeader = rules.egressRules.summaryFiltersStr(c, filtersRelevant, false)
	}
	if needIngress {
		ingressRulesHeader = rules.ingressRules.summaryFiltersStr(c, filtersRelevant, true)
	}
	if needEgress && egressRulesHeader != emptyString {
		egressRulesHeader = "Egress: " + egressRulesHeader + newLine
	}
	if needIngress && ingressRulesHeader != emptyString {
		ingressRulesHeader = "Ingress: " + ingressRulesHeader + newLine
	}
	return egressRulesHeader, ingressRulesHeader
}

// returns a couple of strings of an egress, ingress detailed list of relevant rules; e.g.
// "security group sg1-ky allows connection with the following allow rules
// index: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0
// network ACL acl1-ky blocks connection since there are no relevant allow rules"
func (rules *rulesConnection) ruleDetailsStr(c *VPCConfig, filtersRelevant map[string]bool,
	needEgress, needIngress bool) (egressRulesDetails, ingressRulesDetails string) {
	if needEgress {
		egressRulesDetails = rules.egressRules.rulesDetailsStr(c, filtersRelevant, false)
	}
	if needIngress {
		ingressRulesDetails = rules.ingressRules.rulesDetailsStr(c, filtersRelevant, true)
	}
	if needEgress && egressRulesDetails != emptyString {
		egressRulesDetails = "\tEgress:\n" + egressRulesDetails + newLine
	}
	if needIngress && ingressRulesDetails != emptyString {
		ingressRulesDetails = "\tIngress:\n" + ingressRulesDetails + newLine
	}
	return egressRulesDetails, ingressRulesDetails
}

// returns a string with the effect of each filter by calling StringFilterEffect
// e.g. "security group sg1-ky allows connection; network ACL acl1-ky blocks connection"
func (rules rulesInLayers) summaryFiltersStr(c *VPCConfig, filtersRelevant map[string]bool, isIngress bool) string {
	filtersLayersToPrint := getLayersToPrint(filtersRelevant, isIngress)
	strSlice := make([]string, len(filtersLayersToPrint))
	for i, layer := range filtersLayersToPrint {
		strSlice[i] = stringFilterEffect(c, layer, rules[layer])
	}
	return strings.Join(strSlice, semicolon+space)
}

// for a given layer (e.g. nacl) and []RulesInTable describing ingress/egress rules,
// returns a string with the effect of each filter, called by summaryFiltersStr
func stringFilterEffect(c *VPCConfig, filterLayerName string, rules []RulesInTable) string {
	filterLayer := c.getFilterTrafficResourceOfKind(filterLayerName)
	filtersToActionMap := filterLayer.ListFilterWithAction(rules)
	strSlice := make([]string, len(filtersToActionMap))
	i := 0
	for name, effect := range filtersToActionMap {
		effectStr := ""
		if effect {
			effectStr = " allows connection"
		} else {
			effectStr = " blocks connection"
		}
		strSlice[i] = FilterKindName(filterLayerName) + space + name + effectStr
		i++
	}
	sort.Strings(strSlice)
	return strings.Join(strSlice, semicolon+space)
}

// returns a string with the actual connection path; this can be either a full path from src to dst or a partial path,
// if the connection does not exist. In the latter case the path is until the first block
// e.g.: "vsi1-ky[10.240.10.4] ->  SG sg1-ky -> subnet ... ->  ACL acl1-ky -> PublicGateway: public-gw-ky ->  Public Internet 161.26.0.0/16"
func pathStr(c *VPCConfig, filtersRelevant map[string]bool, src, dst EndpointElem,
	ingressBlocking, egressBlocking bool, externalRouter, crossVpcRouter RoutingResource, crossVpcConnection *connection.Set,
	rules *rulesConnection) string {
	var pathSlice []string
	pathSlice = append(pathSlice, "\t"+src.Name())
	isExternal := src.IsExternal() || dst.IsExternal()
	egressPath := pathFiltersOfIngressOrEgressStr(c, src, filtersRelevant, rules, false, isExternal, externalRouter)
	pathSlice = append(pathSlice, egressPath...)
	externalRouterBlocking := isExternal && externalRouter == nil
	crossVpcRouterInPath := crossVpcRouterRequired(src, dst) // if cross-vpc router needed but missing, will not get here
	if egressBlocking || externalRouterBlocking {
		return blockedPathStr(pathSlice)
	}
	if isExternal {
		externalRouterStr := newLineTab + externalRouter.Kind() + space + externalRouter.Name()
		// externalRouter is fip - add its cidr
		if externalRouter.Kind() == fipRouter {
			externalRouterStr += space + externalRouter.ExternalIP()
		}
		pathSlice = append(pathSlice, externalRouterStr)
	} else if crossVpcRouterInPath { // src and dst are internal and there is a cross vpc Router
		pathSlice = append(pathSlice, newLineTab+src.(InternalNodeIntf).Subnet().VPC().Name(), crossVpcRouter.Kind()+space+crossVpcRouter.Name())
		if crossVpcConnection.IsEmpty() { // cross vpc (tgw) denys connection
			return blockedPathStr(pathSlice)
		}
		pathSlice = append(pathSlice, dst.(InternalNodeIntf).Subnet().VPC().Name())
	}
	ingressPath := pathFiltersOfIngressOrEgressStr(c, dst, filtersRelevant, rules, true, isExternal, externalRouter)
	pathSlice = append(pathSlice, ingressPath...)
	if ingressBlocking {
		return blockedPathStr(pathSlice)
	}
	// got here: full path
	if len(ingressPath) == 0 {
		pathSlice = append(pathSlice, newLineTab+dst.Name())
	} else {
		pathSlice = append(pathSlice, dst.Name())
	}
	return strings.Join(pathSlice, arrow)
}

// terminates a path with a blocking sign, and turns from slice into a path string
func blockedPathStr(pathSlice []string) string {
	pathSlice = append(pathSlice, "|")
	return strings.Join(pathSlice, arrow)
}

// returns a string with the filters (sg and nacl) part of the path above called separately for egress and for ingress
func pathFiltersOfIngressOrEgressStr(c *VPCConfig, node EndpointElem, filtersRelevant map[string]bool, rules *rulesConnection,
	isIngress, isExternal bool, router RoutingResource) []string {
	pathSlice := []string{}
	layers := getLayersToPrint(filtersRelevant, isIngress)
	for _, layer := range layers {
		var allowFiltersOfLayer string
		if isIngress {
			allowFiltersOfLayer = pathFiltersSingleLayerStr(c, layer, rules.ingressRules[layer])
		} else {
			allowFiltersOfLayer = pathFiltersSingleLayerStr(c, layer, rules.egressRules[layer])
		}
		if allowFiltersOfLayer == emptyString {
			break
		}
		pathSlice = append(pathSlice, allowFiltersOfLayer)
		// got here: first layer (security group for egress nacl for ingress) allows connection,
		// subnet is part of the path if both node are internal and there are two layers - sg and nacl
		// subnet should be added after sg in egress and after nacl in ingress
		// or this node internal and externalRouter is pgw
		if !node.IsExternal() && (!isExternal || router.Kind() == pgwKind) &&
			((!isIngress && layer == SecurityGroupLayer && len(layers) > 1) ||
				(isIngress && layer == NaclLayer && len(layers) > 1)) {
			// if !node.isExternal then node is a single internal node implementing InternalNodeIntf
			pathSlice = append(pathSlice, node.(InternalNodeIntf).Subnet().Name())
		}
	}
	if isIngress && len(pathSlice) > 0 {
		pathSlice[0] = newLineTab + pathSlice[0]
	}
	return pathSlice
}

// FilterKindName returns the name of a filter kind within filter layers - e.g. "security group".
func FilterKindName(filterLayer string) string {
	switch filterLayer {
	case NaclLayer:
		return "network ACL"
	case SecurityGroupLayer:
		return "security group"
	default:
		return emptyString
	}
}

// for a given filter layer (e.g. sg) returns a string of the allowing tables
// (note that denying tables are excluded)
func pathFiltersSingleLayerStr(c *VPCConfig, filterLayerName string, rules []RulesInTable) string {
	filterLayer := c.getFilterTrafficResourceOfKind(filterLayerName)
	filtersToActionMap := filterLayer.ListFilterWithAction(rules)
	strSlice := []string{}
	for name, effect := range filtersToActionMap {
		if !effect {
			break
		}
		strSlice = append(strSlice, name)
	}
	// if there are multiple SGs/NACLs effecting the path:
	// ... -> Security Group [SG1,SG2,SG8]
	if len(strSlice) == 1 {
		return FilterKindName(filterLayerName) + " " + strSlice[0]
	} else if len(strSlice) > 1 {
		sort.Strings(strSlice)
		return FilterKindName(filterLayerName) + "[" + strings.Join(strSlice, comma) + "]"
	}
	return emptyString
}

// prints detailed list of rules that effects the (existing or non-existing) connection
func (rules rulesInLayers) rulesDetailsStr(c *VPCConfig, filtersRelevant map[string]bool, isIngress bool) string {
	var strSlice []string
	for _, layer := range getLayersToPrint(filtersRelevant, isIngress) {
		filter := c.getFilterTrafficResourceOfKind(layer)
		if rules, ok := rules[layer]; ok {
			strSlice = append(strSlice, filter.StringDetailsOfRules(rules))
		}
	}
	return strings.Join(strSlice, emptyString)
}

// gets filter Layers valid per filtersRelevant in the order they should be printed
// order of presentation should be same as order of evaluation:
// (1) the SGs attached to the src NIF (2) the outbound rules in the ACL attached to the src NIF's subnet
// (3) the inbound rules in the ACL attached to the dst NIF's subnet (4) the SGs attached to the dst NIF.
// thus, egress: security group first, ingress: nacl first
func getLayersToPrint(filtersRelevant map[string]bool, isIngress bool) (filterLayersOrder []string) {
	var orderedAllFiltersLayers, orderedRelevantFiltersLayers []string
	if isIngress {
		orderedAllFiltersLayers = []string{NaclLayer, SecurityGroupLayer}
	} else {
		orderedAllFiltersLayers = []string{SecurityGroupLayer, NaclLayer}
	}
	for _, layer := range orderedAllFiltersLayers {
		if filtersRelevant[layer] {
			orderedRelevantFiltersLayers = append(orderedRelevantFiltersLayers, layer)
		}
	}
	return orderedRelevantFiltersLayers
}

func (e *detailedConn) respondString() string {
	switch {
	case e.allConn.Equal(e.nonTCP):
		// no tcp component - ill-relevant
		return ""
	case e.tcpRspEnable.IsEmpty():
		// no tcp responsive component
		return "\n\tTCP respond is blocked"
	case e.tcpRspEnable.Equal(e.allConn):
		// tcp responsive component is the entire connection
		return "\n\tThe entire connection is TCP responsive"
	case e.tcpRspDisable.IsEmpty():
		return "\n\tThe TCP sub-connection is responsive"
	default:
		return "\n\tTCP respond is enabled on " + e.tcpRspEnable.String()
	}
}
