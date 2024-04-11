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
const doubleNLWithVars = "\n%v\n%v"
const emptyString = ""

// header of txt/debug format
func explainHeader(explanation *Explanation) string {
	connStr := ""
	if explanation.connQuery != nil {
		connStr = " for " + explanation.connQuery.String()
	}
	srcNetworkInterfaces := listNetworkInterfaces(explanation.srcNetworkInterfacesFromIP)
	dstNetworkInterfaces := listNetworkInterfaces(explanation.dstNetworkInterfacesFromIP)
	header1 := fmt.Sprintf("Connectivity explanation%s between %s%s and %s%s within %v",
		connStr, explanation.src, srcNetworkInterfaces, explanation.dst, dstNetworkInterfaces,
		explanation.c.VPC.Name())
	header2 := strings.Repeat("=", len(header1))
	return header1 + newLine + header2 + doubleNL
}

// in case the src/dst of a network interface given as an internal address connected to network interface returns a string
// of all relevant nodes names
func listNetworkInterfaces(nodes []Node) string {
	if len(nodes) == 0 {
		return emptyString
	}
	networkInterfaces := make([]string, len(nodes))
	for i, node := range nodes {
		networkInterfaces[i] = node.Name()
	}
	return leftParentheses + strings.Join(networkInterfaces, comma) + rightParentheses
}

// String main printing function for the Explanation struct - returns a string with the explanation
func (explanation *Explanation) String(verbose bool) string {
	linesStr := make([]string, len(explanation.groupedLines))
	groupedLines := explanation.groupedLines
	for i, groupedLine := range groupedLines {
		linesStr[i] += groupedLine.explainabilityLineStr(explanation.c, explanation.connQuery, verbose) +
			"------------------------------------------------------------------------------------------------------------------------\n"
	}
	sort.Strings(linesStr)
	return strings.Join(linesStr, newLine) + newLine
}

// prints a single line of explanation for externalAddress grouped <src, dst>
// The printing contains 4 sections:
// 1. Header describing the query and whether there is a connection. E.g.:
// * The following connection exists between ky-vsi0-subnet5[10.240.9.4] and ky-vsi0-subnet11[10.240.80.4]: All Connections
// * No connection between ky-vsi1-subnet20[10.240.128.5] and ky-vsi0-subnet0[10.240.0.5];
// 2. List of all the different resources effecting the connection and the effect of each. E.g.:
// cross-vpc-connection: transit-connection tg_connection0 of transit-gateway local-tg-ky denys connection
// Egress: security group sg21-ky allows connection; network ACL acl21-ky allows connection
// Ingress: network ACL acl1-ky allows connection; security group sg1-ky allows connection
// 3. Connection path description. E.g.:
//	ky-vsi1-subnet20[10.240.128.5] -> security group sg21-ky -> subnet20 -> network ACL acl21-ky ->
//	test-vpc2-ky -> TGW local-tg-ky -> |
// 4. Details of enabling and disabling rules/prefixes, including details of each rule
//
// 1 and 3 are printed always
// 2 is printed only when the connection is blocked. It is redundant when the entire path ("3") is printed. When
// the connection is blocked and only part of the path is printed then 2 is printed so that the relevant information
// is provided regardless of where the is blocking
// 4 is printed only in debug mode

// explainDetails.filtersRelevant,
//
//	explanation.connQuery, line.src, line.dst, line.commonProperties.conn, explainDetails.ingressEnabled,
//	explainDetails.egressEnabled, explainDetails.externalRouter, explainDetails.crossVpcRouter, explainDetails.rules
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
	externalRouter, crossVpcRouter := expDetails.externalRouter, expDetails.crossVpcRouter
	if externalRouter != nil && (src.IsExternal() || dst.IsExternal()) {
		externalRouterHeader = "External traffic via " + externalRouter.Kind() + ": " + externalRouter.Name() + newLine
	}
	var crossVpcConnection *connection.Set
	crossVpcConnection, crossRouterFilterHeader, crossRouterFilterDetails = crossRouterDetails(c, crossVpcRouter, src, dst)
	// noConnection is the 1 above when no connection
	noConnection := noConnectionHeader(src.Name(), dst.Name(), connQuery) + newLine

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
	if verbose {
		details = "\nDetails:\n~~~~~~~~\n" + egressRulesDetails + crossRouterFilterDetails + ingressRulesDetails
	}
	return g.explainPerCaseStr(src, dst, connQuery, crossVpcConnection, ingressBlocking, egressBlocking,
		noConnection, resourceEffectHeader, path, details)
}

// after all data is gathered, generates the actual string to be printed
func (g *groupedConnLine) explainPerCaseStr(src, dst EndpointElem,
	connQuery, crossVpcConnection *connection.Set, ingressBlocking, egressBlocking bool,
	noConnection, resourceEffectHeader, path, details string) string {
	conn := g.commonProperties.conn
	externalRouter, crossVpcRouter := g.commonProperties.expDetails.externalRouter,
		g.commonProperties.expDetails.crossVpcRouter
	headerPlusPath := resourceEffectHeader + path
	switch {
	case crossVpcRouterRequired(src, dst) && crossVpcRouter == nil:
		return fmt.Sprintf("%v\nconnection blocked since src, dst of different VPCs but no transit gateway is defined"+
			doubleNLWithVars, noConnection, headerPlusPath, details)
	case crossVpcRouterRequired(src, dst) && crossVpcRouter != nil && crossVpcConnection.IsEmpty():
		return fmt.Sprintf("%v\nconnection blocked since transit gateway denies route between src and dst"+
			doubleNLWithVars, noConnection, headerPlusPath, details)
	case externalRouter == nil && src.IsExternal():
		return fmt.Sprintf("%v no fip and src is external (fip is required for "+
			"outbound external connection)\n", noConnection)
	case externalRouter == nil && dst.IsExternal():
		return fmt.Sprintf("%v no fip/pgw and dst is external\n", noConnection)
	case ingressBlocking && egressBlocking:
		return fmt.Sprintf("%v connection blocked both by ingress and egress\n%v\n%v", noConnection,
			headerPlusPath, details)
	case ingressBlocking:
		return fmt.Sprintf("%v connection blocked by ingress\n%v\n%v", noConnection,
			headerPlusPath, details)
	case egressBlocking:
		return fmt.Sprintf("%v connection blocked by egress\n%v\n%v", noConnection,
			headerPlusPath, details)
	default: // there is a connection
		return existingConnectionStr(connQuery, src, dst, conn, path, details)
	}
}

func crossRouterDetails(c *VPCConfig, crossVpcRouter RoutingResource, src, dst EndpointElem) (crossVpcConnection *connection.Set,
	crossVpcRouterFilterHeader, crossVpcFilterDetails string) {
	if crossVpcRouter != nil {
		// an error here will pop up earlier, when computing connections
		_, crossVpcConnection, _ := c.getRoutingResource(src.(Node), dst.(Node)) // crossVpc Router (tgw) exists - src, dst are internal
		// if there is a non nil transit gateway then src and dst are vsis, and implement Node
		crossVpcFilterHeader, _ := crossVpcRouter.StringPrefixDetails(src.(Node), dst.(Node), false)
		crossVpcFilterDetails, _ := crossVpcRouter.StringPrefixDetails(src.(Node), dst.(Node), true)
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
	if connQuery == nil {
		return fmt.Sprintf("No connection between %v and %v;", src, dst)
	}
	return fmt.Sprintf("There is no connection \"%v\" between %v and %v;", connQuery.String(), src, dst)
}

// printing when connection exists.
// computing "1" when there is a connection and adding to it already computed "2" and "3" as described in explainabilityLineStr
func existingConnectionStr(connQuery *connection.Set, src, dst EndpointElem,
	conn *connection.Set, path, details string) string {
	resComponents := []string{}
	// Computing the header, "1" described in explainabilityLineStr
	if connQuery == nil {
		resComponents = append(resComponents, fmt.Sprintf("The following connection exists between %v and %v: %v\n", src.Name(), dst.Name(),
			conn.String()))
	} else {
		properSubsetConn := ""
		if !conn.Equal(connQuery) {
			properSubsetConn = " (note that not all queried protocols/ports are allowed)"
		}
		resComponents = append(resComponents, fmt.Sprintf("Connection %v exists between %v and %v%s", conn.String(),
			src.Name(), dst.Name(), properSubsetConn))
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
		egressRulesDetails = "Egress:\n" + egressRulesDetails + newLine
	}
	if needIngress && ingressRulesDetails != emptyString {
		ingressRulesDetails = "Ingress:\n" + ingressRulesDetails + newLine
	}
	return egressRulesDetails, ingressRulesDetails
}

// returns a string with the effect of each filter by calling StringFilterEffect
// e.g. "security group sg1-ky allows connection; network ACL acl1-ky blocks connection"
func (rulesInLayers rulesInLayers) summaryFiltersStr(c *VPCConfig, filtersRelevant map[string]bool, isIngress bool) string {
	filtersLayersToPrint := getLayersToPrint(filtersRelevant, isIngress)
	strSlice := make([]string, len(filtersLayersToPrint))
	for i, layer := range filtersLayersToPrint {
		strSlice[i] = stringFilterEffect(c, layer, rulesInLayers[layer])
	}
	return strings.Join(strSlice, semicolon+space)
}

// for a given layer (e.g. nacl) and []RulesInFilter describing ingress/egress rules,
// returns a string with the effect of each filter, called by summaryFiltersStr
func stringFilterEffect(c *VPCConfig, filterLayerName string, rules []RulesInFilter) string {
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
func pathFiltersSingleLayerStr(c *VPCConfig, filterLayerName string, rules []RulesInFilter) string {
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
func (rulesInLayers rulesInLayers) rulesDetailsStr(c *VPCConfig, filtersRelevant map[string]bool, isIngress bool) string {
	var strSlice []string
	for _, layer := range getLayersToPrint(filtersRelevant, isIngress) {
		filter := c.getFilterTrafficResourceOfKind(layer)
		if rules, ok := rulesInLayers[layer]; ok {
			strSlice = append(strSlice, filter.StringDetailsRulesOfFilter(rules))
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
