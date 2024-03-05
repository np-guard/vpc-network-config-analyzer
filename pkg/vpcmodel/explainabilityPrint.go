package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

const arrow = "->\n"

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

// in case the src/dst of a network interface given as an internal address connected to network interface
func listNetworkInterfaces(nodes []Node) string {
	if len(nodes) == 0 {
		return ""
	}
	networkInterfaces := make([]string, len(nodes))
	for i, node := range nodes {
		networkInterfaces[i] = node.Name()
	}
	return leftParentheses + strings.Join(networkInterfaces, ", ") + rightParentheses
}

// prints each separately without grouping - for debug
func (details *rulesAndConnDetails) String(c *VPCConfig, verbose bool, connQuery *common.ConnectionSet) (string, error) {
	resStr := ""
	for _, srcDstDetails := range *details {
		resStr += stringExplainabilityLine(verbose, c, srcDstDetails.filtersRelevant, connQuery,
			srcDstDetails.src, srcDstDetails.dst, srcDstDetails.conn, srcDstDetails.ingressEnabled,
			srcDstDetails.egressEnabled, srcDstDetails.router, srcDstDetails.actualMergedRules)
	}
	return resStr, nil
}

func (explanation *Explanation) String(verbose bool) string {
	linesStr := make([]string, len(explanation.groupedLines))
	groupedLines := explanation.groupedLines
	for i, line := range groupedLines {
		linesStr[i] += stringExplainabilityLine(verbose, explanation.c, line.commonProperties.expDetails.filtersRelevant,
			explanation.connQuery, line.src, line.dst, line.commonProperties.conn, line.commonProperties.expDetails.ingressEnabled,
			line.commonProperties.expDetails.egressEnabled,
			line.commonProperties.expDetails.router, line.commonProperties.expDetails.rules) +
			"------------------------------------------------------------------------------------------------------------------------\n"
	}
	sort.Strings(linesStr)
	return strings.Join(linesStr, "\n") + "\n"
}

func stringExplainabilityLine(verbose bool, c *VPCConfig, filtersRelevant map[string]bool, connQuery *common.ConnectionSet,
	src, dst EndpointElem, conn *common.ConnectionSet, ingressEnabled, egressEnabled bool,
	router RoutingResource, rules *rulesConnection) string {
	needEgress := !src.IsExternal()
	needIngress := !dst.IsExternal()
	noIngressRules := !ingressEnabled && needIngress
	noEgressRules := !egressEnabled && needEgress
	var routerStr, rulesStr, noConnection, resStr string
	if router != nil && (src.IsExternal() || dst.IsExternal()) {
		routerStr = "External traffic via " + router.Kind() + ": " + router.Name() + "\n"
	}
	routerFiltersHeader := routerStr + rules.getFilterEffectStr(c, filtersRelevant, needEgress, needIngress)
	rulesStr = rules.getRuleDetailsStr(c, filtersRelevant, verbose, needEgress, needIngress)
	if connQuery == nil {
		noConnection = fmt.Sprintf("No connection between %v and %v;", src.Name(), dst.Name())
	} else {
		noConnection = fmt.Sprintf("There is no connection \"%v\" between %v and %v;", connQuery.String(), src.Name(), dst.Name())
	}
	switch {
	case router == nil && src.IsExternal():
		resStr += fmt.Sprintf("%v no fip and src is external (fip is required for "+
			"outbound external connection)\n", noConnection)
	case router == nil && dst.IsExternal():
		resStr += fmt.Sprintf("%v no fip/pgw and dst is external\n", noConnection)
	case noIngressRules && noEgressRules:
		resStr += fmt.Sprintf("%v connection blocked both by ingress and egress\n%v\n%v", noConnection, routerFiltersHeader, rulesStr)
	case noIngressRules:
		resStr += fmt.Sprintf("%v connection blocked by ingress\n%v\n%v", noConnection, routerFiltersHeader, rulesStr)
	case noEgressRules:
		resStr += fmt.Sprintf("%v connection blocked by egress\n%v\n%v", noConnection, routerFiltersHeader, rulesStr)
	default: // there is a connection
		return stringExplainabilityConnection(connQuery, src, dst, conn, routerFiltersHeader, rulesStr)
	}
	return resStr
}

func (rules *rulesConnection) getFilterEffectStr(c *VPCConfig, filtersRelevant map[string]bool, needEgress, needIngress bool) string {
	egressRulesStr, ingressRulesStr := "", ""
	if needEgress {
		egressRulesStr = rules.egressRules.summaryString(c, filtersRelevant, false)
	}
	if needIngress {
		ingressRulesStr = rules.ingressRules.summaryString(c, filtersRelevant, true)
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

func (rules *rulesConnection) getRuleDetailsStr(c *VPCConfig, filtersRelevant map[string]bool,
	verbose, needEgress, needIngress bool) string {
	if !verbose {
		return ""
	}
	egressRulesStr, ingressRulesStr := "", ""
	if needEgress {
		egressRulesStr = rules.egressRules.detailsString(c, filtersRelevant, false)
	}
	if needIngress {
		ingressRulesStr = rules.ingressRules.detailsString(c, filtersRelevant, true)
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

func stringExplainabilityConnection(connQuery *common.ConnectionSet, src, dst EndpointElem,
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

// prints effect of each filter by calling StringFilterEffect
func (rulesInLayers rulesInLayers) summaryString(c *VPCConfig, filtersRelevant map[string]bool, isIngress bool) string {
	filtersLayersToPrint := getLayersToPrint(filtersRelevant, isIngress)
	strSlice := make([]string, len(filtersLayersToPrint))
	for i, layer := range filtersLayersToPrint {
		strSlice[i] = stringFilterEffect(c, layer, rulesInLayers[layer])
	}
	return strings.Join(strSlice, semicolon+" ")
}

// in cases there *is* a connection - prints the path, e.g.
// vsi1-ky[10.240.10.4] ->  SG sg1-ky -> subnet ... ->  ACL acl1-ky -> PublicGateway: public-gw-ky ->  Public Internet 161.26.0.0/16
func stringExplainPath(c *VPCConfig, filtersRelevant map[string]bool, src, dst EndpointElem,
	ingressEnabled, egressEnabled bool, router RoutingResource, rules *rulesConnection) string {
	var pathSlice []string
	pathSlice = append(pathSlice, src.Name())
	isExternal := src.IsExternal() || dst.IsExternal()
	egressPath := stringExplainFiltersLayersPath(c, src, filtersRelevant, rules, false, isExternal, router)
	pathSlice = append(pathSlice, egressPath...)
	routerBlocking := isExternal && router == nil
	if !egressEnabled || routerBlocking {
		return blockedPathStr(pathSlice)
	}
	if isExternal {
		pathSlice = append(pathSlice, router.Kind()+" "+router.Name())
	}
	ingressPath := stringExplainFiltersLayersPath(c, dst, filtersRelevant, rules, true, isExternal, router)
	pathSlice = append(pathSlice, ingressPath...)
	if !ingressEnabled {
		return blockedPathStr(pathSlice)
	}
	return strings.Join(pathSlice, arrow)
}

func stringExplainFiltersLayersPath(c *VPCConfig, node EndpointElem, filtersRelevant map[string]bool, rules *rulesConnection,
	isIngress, isExternal bool, router RoutingResource) []string {
	var pathSlice []string
	layers := getLayersToPrint(filtersRelevant, isIngress)
	for i, layer := range layers {
		allowFiltersOfLayer := stringFilterLayerPath(c, layer, rules.egressRules[layer])
		if len(allowFiltersOfLayer) == 0 {
			break
		}
		pathSlice = append(pathSlice, allowFiltersOfLayer)
		// got here: first layer (security group for egress nacl for ingress) allows connection,
		// subnet is part of the path if both node are internal or this node internal and router is pgw
		if !node.IsExternal() && (!isExternal || router.Kind() == pgwKind) &&
			((!isIngress && layer == SecurityGroupLayer && layers[i+1] == NaclLayer) ||
				(isIngress && layer == NaclLayer && layers[i+1] == SecurityGroupLayer)) {
			// if !node.isExternal then node is a single internal node implementing InternalNodeIntf
			pathSlice = append(pathSlice, node.(InternalNodeIntf).Subnet().Name())
		}
	}
	return pathSlice
}

func blockedPathStr(pathSlice []string) string {
	pathSlice = append(pathSlice, "|")
	return strings.Join(pathSlice, arrow)
}

func stringFilterLayerPath(c *VPCConfig, filterLayerName string, rules []RulesInFilter) string {
	filterLayer := c.getFilterTrafficResourceOfKind(filterLayerName)
	filtersToActionMap := filterLayer.ListFilterWithAction(rules)
	strSlice := make([]string, len(filtersToActionMap))
	i := 0
	for name, effect := range filtersToActionMap {
		if !effect {
			break
		}
		strSlice[i] = name
	}
	if len(strSlice) == 1 {
		return filterLayer.Name() + " " + strSlice[0]
	} else if len(strSlice) > 1 {
		return "[" + strings.Join(strSlice, ", ") + "]"
	}
	return ""
}

// prints detailed list of rules that effects the (existing or non-existing) connection
func (rulesInLayers rulesInLayers) detailsString(c *VPCConfig, filtersRelevant map[string]bool, isIngress bool) string {
	var strSlice []string
	for _, layer := range getLayersToPrint(filtersRelevant, isIngress) {
		filter := c.getFilterTrafficResourceOfKind(layer)
		if rules, ok := rulesInLayers[layer]; ok {
			strSlice = append(strSlice, filter.StringDetailsRulesOfFilter(rules))
		}
	}
	return strings.Join(strSlice, "")
}

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
		strSlice[i] = filterLayer.Name() + " " + name + effectStr
		i++
	}
	return strings.Join(strSlice, semicolon+" ")
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
