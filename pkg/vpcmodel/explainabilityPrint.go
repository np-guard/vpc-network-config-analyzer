package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const arrow = " -> "
const newLineTab = "\n\t"
const space = " "
const comma = ", "

// header of txt/debug format
func explainHeader(explanation *Explanation) string {
	connStr := ""
	if explanation.connQuery != nil {
		connStr = " for " + explanation.connQuery.String()
	}
	srcNetworkInterfaces := listNetworkInterfaces(explanation.srcNetworkInterfacesFromIP)
	dstNetworkInterfaces := listNetworkInterfaces(explanation.dstNetworkInterfacesFromIP)
	header1 := fmt.Sprintf("Connectivity explanation%s between %s%s and %s%s",
		connStr, explanation.src, srcNetworkInterfaces, explanation.dst, dstNetworkInterfaces)
	header2 := strings.Repeat("=", len(header1))
	return header1 + "\n" + header2 + "\n\n"
}

// in case the src/dst of a network interface given as an internal address connected to network interface returns a string
// of all relevant nodes names
func listNetworkInterfaces(nodes []Node) string {
	if len(nodes) == 0 {
		return ""
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
	for i, line := range groupedLines {
		linesStr[i] += explainabilityLineStr(verbose, explanation.c, line.commonProperties.expDetails.filtersRelevant,
			explanation.connQuery, line.src, line.dst, line.commonProperties.conn, line.commonProperties.expDetails.ingressEnabled,
			line.commonProperties.expDetails.egressEnabled,
			line.commonProperties.expDetails.router, line.commonProperties.expDetails.rules) +
			"------------------------------------------------------------------------------------------------------------------------\n"
	}
	sort.Strings(linesStr)
	return strings.Join(linesStr, "\n") + "\n"
}

// main printing function for a *rulesAndConnDetails <src, dst> line (before grouping); calls explainabilityLineStr
// used only for testing; the txt and debug output are through grouping results
func (details *rulesAndConnDetails) String(c *VPCConfig, verbose bool, connQuery *common.ConnectionSet) (string, error) {
	resStr := ""
	for _, srcDstDetails := range *details {
		resStr += explainabilityLineStr(verbose, c, srcDstDetails.filtersRelevant, connQuery,
			srcDstDetails.src, srcDstDetails.dst, srcDstDetails.conn, srcDstDetails.ingressEnabled,
			srcDstDetails.egressEnabled, srcDstDetails.router, srcDstDetails.actualMergedRules)
	}
	return resStr, nil
}

// prints a single line of <src, dst>. Called either with grouping results or from the original struct before grouping
func explainabilityLineStr(verbose bool, c *VPCConfig, filtersRelevant map[string]bool, connQuery *common.ConnectionSet,
	src, dst EndpointElem, conn *common.ConnectionSet, ingressEnabled, egressEnabled bool,
	router RoutingResource, rules *rulesConnection) string {
	needEgress := !src.IsExternal()
	needIngress := !dst.IsExternal()
	ingressBlocking := !ingressEnabled && needIngress
	egressBlocking := !egressEnabled && needEgress
	var routerStr, rulesStr, resStr string
	if router != nil && (src.IsExternal() || dst.IsExternal()) {
		routerStr = "External traffic via " + router.Kind() + ": " + router.Name() + "\n"
	}
	var routerFiltersHeader string
	if conn.IsEmpty() {
		routerFiltersHeader = routerStr + rules.filterEffectStr(c, filtersRelevant, needEgress, needIngress) + "\n"
	}
	path := "Path:\n" + pathStr(c, filtersRelevant, src, dst,
		ingressBlocking, egressBlocking, router, rules)
	rulesStr = rules.ruleDetailsStr(c, filtersRelevant, verbose, needEgress, needIngress)
	noConnection := noConnectionHeader(src.Name(), dst.Name(), connQuery)
	routerFiltersHeaderPlusPath := routerFiltersHeader + path
	switch {
	case router == nil && src.IsExternal():
		resStr += fmt.Sprintf("%v no fip and src is external (fip is required for "+
			"outbound external connection)\n", noConnection)
	case router == nil && dst.IsExternal():
		resStr += fmt.Sprintf("%v no fip/pgw and dst is external\n", noConnection)
	case ingressBlocking && egressBlocking:
		resStr += fmt.Sprintf("%v connection blocked both by ingress and egress\n%v\n%v", noConnection,
			routerFiltersHeaderPlusPath, rulesStr)
	case ingressBlocking:
		resStr += fmt.Sprintf("%v connection blocked by ingress\n%v\n%v", noConnection,
			routerFiltersHeaderPlusPath, rulesStr)
	case egressBlocking:
		resStr += fmt.Sprintf("%v connection blocked by egress\n%v\n%v", noConnection,
			routerFiltersHeaderPlusPath, rulesStr)
	default: // there is a connection
		return existingConnectionStr(connQuery, src, dst, conn, routerFiltersHeaderPlusPath, rulesStr)
	}
	return resStr
}

// returns string of header in case a connection fails to exist
func noConnectionHeader(src, dst string, connQuery *common.ConnectionSet) string {
	if connQuery == nil {
		return fmt.Sprintf("No connection between %v and %v;", src, dst)
	}
	return fmt.Sprintf("There is no connection \"%v\" between %v and %v;", connQuery.String(), src, dst)
}

// return a string with the described existing connection and relevant details w.r.t. the potential query
// e.g.: "Connection protocol: UDP src-ports: 1-600 dst-ports: 1-50 exists between vsi1-ky[10.240.10.4]
// and Public Internet 161.26.0.0/16 (note that not all queried protocols/ports are allowed)"
func existingConnectionStr(connQuery *common.ConnectionSet, src, dst EndpointElem,
	conn *common.ConnectionSet, filtersEffectStr, rulesStr string) string {
	resStr := ""
	if connQuery == nil {
		resStr = fmt.Sprintf("The following connection exists between %v and %v: %v\n", src.Name(), dst.Name(),
			conn.String())
	} else {
		properSubsetConn := ""
		if !conn.Equal(connQuery) {
			properSubsetConn = " (note that not all queried protocols/ports are allowed)"
		}
		resStr = fmt.Sprintf("Connection %v exists between %v and %v%s\n", conn.String(),
			src.Name(), dst.Name(), properSubsetConn)
	}
	resStr += filtersEffectStr + "\n" + rulesStr
	return resStr
}

// returns a string with a summary of each filter (table) effect; e.g.
// "Egress: security group sg1-ky allows connection; network ACL acl1-ky blocks connection
// Ingress: network ACL acl3-ky allows connection; security group sg1-ky allows connection"
func (rules *rulesConnection) filterEffectStr(c *VPCConfig, filtersRelevant map[string]bool, needEgress, needIngress bool) string {
	egressRulesStr, ingressRulesStr := "", ""
	if needEgress {
		egressRulesStr = rules.egressRules.summaryFiltersStr(c, filtersRelevant, false)
	}
	if needIngress {
		ingressRulesStr = rules.ingressRules.summaryFiltersStr(c, filtersRelevant, true)
	}
	if needEgress && egressRulesStr != "" {
		egressRulesStr = "Egress: " + egressRulesStr
	}
	if needIngress && ingressRulesStr != "" {
		ingressRulesStr = "Ingress: " + ingressRulesStr
	}
	if egressRulesStr != "" && ingressRulesStr != "" {
		return egressRulesStr + "\n" + ingressRulesStr
	}
	return egressRulesStr + ingressRulesStr
}

// returns a string with a detailed list of relevant rules; e.g.
// "security group sg1-ky allows connection with the following allow rules
// index: 0, direction: outbound, protocol: all, cidr: 0.0.0.0/0
// network ACL acl1-ky blocks connection since there are no relevant allow rules"
func (rules *rulesConnection) ruleDetailsStr(c *VPCConfig, filtersRelevant map[string]bool,
	verbose, needEgress, needIngress bool) string {
	if !verbose {
		return ""
	}
	egressRulesStr, ingressRulesStr := "", ""
	if needEgress {
		egressRulesStr = rules.egressRules.rulesDetailsStr(c, filtersRelevant, false)
	}
	if needIngress {
		ingressRulesStr = rules.ingressRules.rulesDetailsStr(c, filtersRelevant, true)
	}
	if needEgress && egressRulesStr != "" {
		egressRulesStr = "Egress:\n" + egressRulesStr
	}
	if needIngress && ingressRulesStr != "" {
		ingressRulesStr = "Ingress:\n" + ingressRulesStr
		if needEgress && egressRulesStr != "" {
			egressRulesStr += "\n"
		}
	}
	if egressRulesStr != "" || ingressRulesStr != "" {
		return "\nDetails:\n~~~~~~~~\n" + egressRulesStr + ingressRulesStr
	}
	return ""
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
	ingressBlocking, egressBlocking bool, router RoutingResource, rules *rulesConnection) string {
	var pathSlice []string
	pathSlice = append(pathSlice, "\t"+src.Name())
	isExternal := src.IsExternal() || dst.IsExternal()
	egressPath := pathFiltersOfIngressOrEgressStr(c, src, filtersRelevant, rules, false, isExternal, router)
	pathSlice = append(pathSlice, egressPath...)
	routerBlocking := isExternal && router == nil
	if egressBlocking || routerBlocking {
		return blockedPathStr(pathSlice)
	}
	if isExternal {
		pathSlice = append(pathSlice, newLineTab+router.Kind()+space+router.Name())
	}
	ingressPath := pathFiltersOfIngressOrEgressStr(c, dst, filtersRelevant, rules, true, isExternal, router)
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
		if allowFiltersOfLayer == "" {
			break
		}
		pathSlice = append(pathSlice, allowFiltersOfLayer)
		// got here: first layer (security group for egress nacl for ingress) allows connection,
		// subnet is part of the path if both node are internal and there are two layers - sg and nacl
		// subnet should be added after sg in egress and after nacl in ingress
		// or this node internal and router is pgw
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
		return ""
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
	return ""
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
	return strings.Join(strSlice, "")
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
