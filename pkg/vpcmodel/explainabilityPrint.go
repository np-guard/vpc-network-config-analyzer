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
const blockedLeft = "| "
const blockedRight = " |"

func explainHeader(explanation *Explanation) string {
	singleVpcContext := ""
	// communication within a single vpc
	if explanation.c != nil && !explanation.c.IsMultipleVPCsConfig {
		singleVpcContext = fmt.Sprintf(" within %v", explanation.c.VPC.Name())
	}
	title := fmt.Sprintf("Explaining connectivity from %s to %s%s%s",
		explanation.src, explanation.dst, singleVpcContext, connHeader(explanation.connQuery))
	var srcInterpretation, dstInterpretation string
	// ToDo srcNodes, dstNodes is empty when no cross-vpc router connects src and dst.
	//      See https://github.com/np-guard/vpc-network-config-analyzer/issues/655
	if len(explanation.srcNodes) > 0 && len(explanation.dstNodes) > 0 {
		srcInterpretation = fmt.Sprintf("Interpreted source: %s\n", endPointInterpretation(explanation.c,
			explanation.src, explanation.srcNodes))
		dstInterpretation = fmt.Sprintf("Interpreted destination: %s\n", endPointInterpretation(explanation.c,
			explanation.dst, explanation.dstNodes))
	}
	underLine := strings.Repeat("=", len(title))
	return title + newLine + srcInterpretation + dstInterpretation + underLine + doubleNL
}

// connHeader is used to print 1) the query in the first header
// 2) the actual allowed connection from the queried one in the 2nd header
func connHeader(connQuery *connection.Set) string {
	if connQuery != nil {
		return " using \"" + connQuery.String() + "\""
	}
	return ""
}

// in case the src/dst is not external address, returns a string of all relevant nodes names
func endPointInterpretation(c *VPCConfig, userInput string, nodes []Node) string {
	if nodes[0].IsExternal() {
		return userInput + " (external)"
	}
	networkInterfaces := make([]string, len(nodes))
	for i, node := range nodes {
		networkInterfaces[i] = node.ExtendedName(c)
	}
	return strings.Join(networkInterfaces, comma)
}

// String main printing function for the Explanation struct - returns a string with the explanation
func (explanation *Explanation) String(verbose bool) string {
	if explanation.c == nil { // no VPCConfig - missing cross-VPC router (tgw)
		return explainMissingCrossVpcRouter(explanation.src, explanation.dst, explanation.connQuery)
	}
	linesStr := make([]string, len(explanation.groupedLines))
	groupedLines := explanation.groupedLines
	for i, groupedLine := range groupedLines {
		linesStr[i] += groupedLine.explainabilityLineStr(explanation.c, explanation.connQuery, explanation.allRulesDetails, verbose) +
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
//     * Connections from ky-vsi0-subnet5[10.240.9.4] to ky-vsi0-subnet11[10.240.80.4]: All Connections
//     The TCP sub-connection is responsive
//     * No connections from from ky-vsi1-subnet20[10.240.128.5] to ky-vsi0-subnet0[10.240.0.5];
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
//
// 1 and 3 are printed always
// 2 is printed only when the connection is blocked. It is redundant when the entire path ("3") is printed. When
// the connection is blocked and only part of the path is printed then 2 is printed so that the relevant information
// is provided regardless of where the is blocking
// 4 is printed only in detailed mode
func (g *groupedConnLine) explainabilityLineStr(c *VPCConfig, connQuery *connection.Set, allRulesDetails *rulesDetails,
	verbose bool) string {
	expDetails := g.CommonProperties.expDetails
	filtersRelevant := g.CommonProperties.expDetails.filtersRelevant
	src, dst := g.Src, g.Dst
	loadBalancerRule := g.CommonProperties.expDetails.loadBalancerRule
	needEgress := !src.IsExternal()
	needIngress := !dst.IsExternal()
	loadBalancerBlocking := loadBalancerRule != nil && loadBalancerRule.Deny()
	ingressBlocking := !expDetails.ingressEnabled && needIngress
	egressBlocking := !expDetails.egressEnabled && needEgress
	var externalRouterHeader, crossRouterFilterHeader, loadBalancerHeader, resourceEffectHeader,
		crossRouterFilterDetails, loadBalancerDetails, details string
	externalRouter, crossVpcRouter, crossVpcRules := expDetails.externalRouter, expDetails.crossVpcRouter, expDetails.crossVpcRules
	if externalRouter != nil && (src.IsExternal() || dst.IsExternal()) {
		externalRouterHeader = "External traffic via " + externalRouter.Kind() + ": " + externalRouter.Name() + newLine
	}
	if loadBalancerRule != nil {
		loadBalancerHeader = "Load Balancer: " + loadBalancerRule.String()
		loadBalancerDetails = "\tLoad Balancer:\n\t\t" + loadBalancerRule.String() + newLine
	}
	var crossVpcConnection *connection.Set
	crossVpcConnection, crossRouterFilterHeader, crossRouterFilterDetails = crossRouterDetails(c, crossVpcRouter,
		crossVpcRules, src, dst)
	// noConnection is the 1 above when no connection
	noConnection := noConnectionHeader(src.ExtendedName(c), dst.ExtendedName(c), connQuery) + newLine

	// resourceEffectHeader is "2" above
	rules := expDetails.rules
	egressRulesHeader, ingressRulesHeader := rules.filterEffectStr(allRulesDetails, filtersRelevant, needEgress, needIngress)
	resourceEffectHeader = loadBalancerHeader + externalRouterHeader + egressRulesHeader + crossRouterFilterHeader +
		ingressRulesHeader + newLine

	// path in "3" above
	path := "Path:\n" + pathStr(allRulesDetails, filtersRelevant, src, dst,
		ingressBlocking, egressBlocking, loadBalancerBlocking, externalRouter, crossVpcRouter, crossVpcConnection, rules) + newLine
	// details is "4" above
	egressRulesDetails, ingressRulesDetails := rules.ruleDetailsStr(allRulesDetails, filtersRelevant, needEgress, needIngress)
	conn := g.CommonProperties.Conn
	if verbose {
		enabledOrDisabledStr := "enabled"
		if conn.allConn.IsEmpty() {
			enabledOrDisabledStr = "disabled"
		}
		details = "\nDetails:\n~~~~~~~~\nPath is " + enabledOrDisabledStr + "; The relevant rules are:\n" +
			loadBalancerDetails + egressRulesDetails + crossRouterFilterDetails + ingressRulesDetails
		if respondRulesRelevant(conn, filtersRelevant, crossVpcRouter) {
			respondEgressDetails, respondsIngressDetails, crossVpcRespondDetails := "", "", ""
			// for respond rules needIngress and needEgress are switched
			if filtersRelevant[statelessLayerName] {
				respondEgressDetails, respondsIngressDetails = expDetails.respondRules.ruleDetailsStr(allRulesDetails,
					filtersRelevant, needIngress, needEgress)
			}
			if expDetails.crossVpcRouter != nil {
				crossVpcRespondDetails, _ = crossVpcRouter.StringOfRouterRules(expDetails.crossVPCRespondRules,
					true)
			}
			details += respondDetailsHeader(conn) + respondEgressDetails + crossVpcRespondDetails +
				respondsIngressDetails
		}
	}
	return g.explainPerCaseStr(c, src, dst, connQuery, crossVpcConnection, ingressBlocking, egressBlocking, loadBalancerBlocking,
		noConnection, resourceEffectHeader, path, details)
}

// assumption: the func is called only if the tcp component of the connection is not empty
func respondDetailsHeader(d *detailedConn) string {
	switch {
	case d.TCPRspDisable.IsEmpty():
		return "TCP response is enabled; The relevant rules are:\n"
	case d.tcpRspEnable.IsEmpty():
		return "TCP response is disabled; The relevant rules are:\n"
	default:
		return "TCP response is partly enabled; The relevant rules are:\n"
	}
}

// after all data is gathered, generates the actual string to be printed
func (g *groupedConnLine) explainPerCaseStr(c *VPCConfig, src, dst EndpointElem,
	connQuery, crossVpcConnection *connection.Set, ingressBlocking, egressBlocking, loadBalancerBlocking bool,
	noConnection, resourceEffectHeader, path, details string) string {
	conn := g.CommonProperties.Conn
	externalRouter, crossVpcRouter := g.CommonProperties.expDetails.externalRouter,
		g.CommonProperties.expDetails.crossVpcRouter
	headerPlusPath := resourceEffectHeader + path
	switch {
	case crossVpcRouterRequired(src, dst) && crossVpcRouter != nil && crossVpcConnection.IsEmpty():
		return fmt.Sprintf("%vAll connections will be blocked since transit gateway denies route from source to destination"+tripleNLVars,
			noConnection, headerPlusPath, details)
	case externalRouter == nil && src.IsExternal():
		return fmt.Sprintf("%v\tThere is no resource enabling inbound external connectivity\n", noConnection)
	case externalRouter == nil && dst.IsExternal():
		return fmt.Sprintf("%v\tThe dst is external but there is no resource enabling external connectivity\n",
			noConnection)
	case ingressBlocking || egressBlocking || loadBalancerBlocking:
		return fmt.Sprintf("%v%s"+tripleNLVars, noConnection,
			blockSummary(ingressBlocking, egressBlocking, loadBalancerBlocking),
			headerPlusPath, details)
	default: // there is a connection
		return existingConnectionStr(c, connQuery, src, dst, conn, path, details)
	}
}

// blockSummary() return a summary of the rules that block the connection, for example:
// "connection is blocked both by ingress and egress, and will not be initiated by Load Balancer"
func blockSummary(ingressBlocking, egressBlocking, loadBalancerBlocking bool) string {
	blockedBy := []string{}
	if ingressBlocking {
		blockedBy = append(blockedBy, "ingress")
	}
	if egressBlocking {
		blockedBy = append(blockedBy, "egress")
	}
	l := len(blockedBy)
	var blockedByString []string
	switch l {
	case 1:
		blockedByString = append(blockedByString, fmt.Sprintf("is blocked by %s", blockedBy[0]))
	case 2:
		blockedByString = append(blockedByString, fmt.Sprintf("is blocked both by %s and %s", blockedBy[0], blockedBy[1]))
	}

	if loadBalancerBlocking {
		blockedByString = append(blockedByString, "will not be initiated by Load Balancer")
	}
	return "connection " + strings.Join(blockedByString, ", and ")
}

func crossRouterDetails(c *VPCConfig, crossVpcRouter RoutingResource, crossVpcRules []RulesInTable,
	src, dst EndpointElem) (crossVpcConnection *connection.Set,
	crossVpcRouterFilterHeader, crossVpcFilterDetails string) {
	if crossVpcRouter != nil {
		// an error here will pop up earlier, when computing connections
		_, crossVpcConnection, _ := c.getRoutingResource(src.(Node), dst.(Node)) // crossVpc Router (tgw) exists - src, dst are internal
		// if there is a non nil transit gateway then src and dst are vsis, and implement Node
		crossVpcFilterHeader, _ := crossVpcRouter.StringOfRouterRules(crossVpcRules, false)
		crossVpcFilterDetails, _ := crossVpcRouter.StringOfRouterRules(crossVpcRules, true)
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
	return fmt.Sprintf("No connections from %s to %s%s;", src, dst, connHeader(connQuery))
}

// printing when connection exists.
// computing "1" when there is a connection and adding to it already computed "2" and "3" as described in explainabilityLineStr
func existingConnectionStr(c *VPCConfig, connQuery *connection.Set, src, dst EndpointElem,
	conn *detailedConn, path, details string) string {
	resComponents := []string{}
	// Computing the header, "1" described in explainabilityLineStr
	respondConnStr := respondString(conn)
	if connQuery == nil {
		resComponents = append(resComponents, fmt.Sprintf("Connections from %v to %v: %v%v\n", src.ExtendedName(c), dst.ExtendedName(c),
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
func (rules *rulesConnection) filterEffectStr(allRulesDetails *rulesDetails, filtersRelevant map[string]bool, needEgress,
	needIngress bool) (egressRulesHeader, ingressRulesHeader string) {
	if needEgress {
		egressRulesHeader = rules.egressRules.summaryFiltersStr(allRulesDetails, filtersRelevant, false)
	}
	if needIngress {
		ingressRulesHeader = rules.ingressRules.summaryFiltersStr(allRulesDetails, filtersRelevant, true)
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
func (rules *rulesConnection) ruleDetailsStr(allRulesDetails *rulesDetails, filtersRelevant map[string]bool,
	needEgress, needIngress bool) (egressRulesDetails, ingressRulesDetails string) {
	if needEgress {
		egressRulesDetails = rules.egressRules.rulesDetailsStr(allRulesDetails, filtersRelevant, false)
	}
	if needIngress {
		ingressRulesDetails = rules.ingressRules.rulesDetailsStr(allRulesDetails, filtersRelevant, true)
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
func (rules rulesInLayers) summaryFiltersStr(allRulesDetails *rulesDetails, filtersRelevant map[string]bool,
	isIngress bool) string {
	filtersLayersToPrint := getLayersToPrint(filtersRelevant, isIngress)
	strSlice := make([]string, len(filtersLayersToPrint))
	for i, layer := range filtersLayersToPrint {
		strSlice[i] = stringFilterEffect(allRulesDetails, layer, rules[layer])
	}
	return strings.Join(strSlice, semicolon+space)
}

// for a given layer (e.g. nacl) and []RulesInTable describing ingress/egress rules,
// returns a string with the effect of each filter, called by summaryFiltersStr
func stringFilterEffect(allRulesDetails *rulesDetails, filterLayerName string, rules []RulesInTable) string {
	filtersToActionMap := allRulesDetails.listFilterWithAction(filterLayerName, rules)
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
// if the connection does not exist. In the latter case the path is until the first block with the first block between ||
// e.g.: "vsi1-ky[10.240.10.4] ->  SG sg1-ky -> subnet ... ->  ACL acl1-ky -> PublicGateway: public-gw-ky ->  Public Internet 161.26.0.0/16"
// e.g.: "vsi1-ky[10.240.10.4] -> security group sg1-ky -> subnet1-ky -> | network ACL acl1-ky |"
func pathStr(allRulesDetails *rulesDetails, filtersRelevant map[string]bool, src, dst EndpointElem,
	ingressBlocking, egressBlocking, loadBalancerBlocking bool,
	externalRouter, crossVpcRouter RoutingResource, crossVpcConnection *connection.Set,
	rules *rulesConnection) string {
	var pathSlice []string
	pathSlice = append(pathSlice, "\t"+src.Name())
	if loadBalancerBlocking {
		// todo: add loadBalancer as part of the path and also as blocking??? separate PR?
		// connection is stopped at the src itself:
		return blockedPathStr(pathSlice)
	}
	isExternal := src.IsExternal() || dst.IsExternal()
	egressPath := pathFiltersOfIngressOrEgressStr(allRulesDetails, src, filtersRelevant, rules, false, isExternal, externalRouter)
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
		pathSlice = append(pathSlice, newLineTab+src.(InternalNodeIntf).Subnet().VPC().Name(),
			crossVpcRouter.Kind()+space+crossVpcRouter.Name())
		if crossVpcConnection.IsEmpty() { // cross vpc (tgw) denys connection
			pathSlice[len(pathSlice)-1] = blockedLeft + pathSlice[len(pathSlice)-1] // blocking cross-vpc router
			return blockedPathStr(pathSlice)
		}
		pathSlice = append(pathSlice, dst.(InternalNodeIntf).Subnet().VPC().Name())
	}
	ingressPath := pathFiltersOfIngressOrEgressStr(allRulesDetails, dst, filtersRelevant, rules, true,
		isExternal, externalRouter)
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
	pathSlice[len(pathSlice)-1] = pathSlice[len(pathSlice)-1] + blockedRight
	return strings.Join(pathSlice, arrow)
}

// returns a string with the filters (sg and nacl) part of the path above called separately for egress and for ingress
//
//nolint:gocyclo // better not split into two function
func pathFiltersOfIngressOrEgressStr(allRulesDetails *rulesDetails, node EndpointElem,
	filtersRelevant map[string]bool, rules *rulesConnection,
	isIngress, isExternal bool, router RoutingResource) []string {
	pathSlice := []string{}
	layers := getLayersToPrint(filtersRelevant, isIngress)
	for _, layer := range layers {
		var allowFiltersOfLayer, denyTable string
		if isIngress {
			allowFiltersOfLayer, denyTable = pathFiltersSingleLayerStr(allRulesDetails, layer, rules.ingressRules[layer])
		} else {
			allowFiltersOfLayer, denyTable = pathFiltersSingleLayerStr(allRulesDetails, layer, rules.egressRules[layer])
		}
		if allowFiltersOfLayer != emptyString {
			pathSlice = append(pathSlice, allowFiltersOfLayer)
		}
		if denyTable != emptyString {
			pathSlice = append(pathSlice, blockedLeft+denyTable)
			break
		}
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

// for a given filter layer (e.g. sg) returns a string of the allowing tables (note that denying tables are excluded),
// and the name of the denying table, if any
func pathFiltersSingleLayerStr(allRulesDetails *rulesDetails, filterLayerName string,
	rules []RulesInTable) (allowPath, denyTable string) {
	filtersToActionMap := allRulesDetails.listFilterWithAction(filterLayerName, rules)
	strSlice := []string{}
	for name, effect := range filtersToActionMap {
		if !effect {
			denyTable = FilterKindName(filterLayerName) + space + name
			break
		}
		strSlice = append(strSlice, name)
	}
	// if there are multiple SGs/NACLs effecting the path:
	// ... -> Security Group [SG1,SG2,SG8]
	if len(strSlice) == 1 {
		return FilterKindName(filterLayerName) + space + strSlice[0], denyTable
	} else if len(strSlice) > 1 {
		sort.Strings(strSlice)
		return FilterKindName(filterLayerName) + "[" + strings.Join(strSlice, comma) + "]", denyTable
	}
	return emptyString, denyTable
}

// prints detailed list of rules that effects the (existing or non-existing) connection
func (rules rulesInLayers) rulesDetailsStr(allRulesDetails *rulesDetails, filtersRelevant map[string]bool,
	isIngress bool) string {
	var strSlice []string
	for _, layer := range getLayersToPrint(filtersRelevant, isIngress) {
		if rulesInLayer, ok := rules[layer]; ok {
			strSlice = append(strSlice, allRulesDetails.stringDetailsOfLayer(layer, rulesInLayer))
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

func respondString(d *detailedConn) string {
	switch {
	case d.allConn.Equal(d.nonTCP) || d.TCPRspDisable.IsEmpty():
		// no tcp component - ill-relevant; entire TCP connection is responsive - nothing to print
		return ""
	case d.tcpRspEnable.IsEmpty():
		// no tcp responsive component
		return "\n\tTCP response is blocked"
	default:
		disabledToPrint := strings.ReplaceAll(d.TCPRspDisable.String(),
			"protocol: ", "")
		disabledToPrint = strings.ReplaceAll(disabledToPrint, "TCP ", "")
		return "\n\tHowever, TCP response is blocked for: " + disabledToPrint
	}
}
