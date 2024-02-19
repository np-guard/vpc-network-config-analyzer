package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

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
		resStr += stringExplainabilityLine(verbose, c, connQuery, srcDstDetails.src, srcDstDetails.dst, srcDstDetails.conn,
			srcDstDetails.ingressEnabled, srcDstDetails.egressEnabled, srcDstDetails.router, srcDstDetails.actualMergedRules)
	}
	return resStr, nil
}

func (explanation *Explanation) String(verbose bool) string {
	linesStr := make([]string, len(explanation.groupedLines))
	groupedLines := explanation.groupedLines
	for i, line := range groupedLines {
		linesStr[i] += stringExplainabilityLine(verbose, explanation.c, explanation.connQuery, line.src, line.dst, line.commonProperties.conn,
			line.commonProperties.expDetails.ingressEnabled, line.commonProperties.expDetails.egressEnabled,
			line.commonProperties.expDetails.router, line.commonProperties.expDetails.rules) +
			"------------------------------------------------------------------------------------------------------------------------\n"
	}
	sort.Strings(linesStr)
	return strings.Join(linesStr, "\n") + "\n"
}

func stringExplainabilityLine(verbose bool, c *VPCConfig, connQuery *common.ConnectionSet, src, dst EndpointElem,
	conn *common.ConnectionSet, ingressEnabled, egressEnabled bool,
	router RoutingResource, rules *rulesConnection) string {
	needEgress := !src.IsExternal()
	needIngress := !dst.IsExternal()
	noIngressRules := !ingressEnabled && needIngress
	noEgressRules := !egressEnabled && needEgress
	var routerStr, rulesStr, noConnection, resStr string
	if router != nil && (src.IsExternal() || dst.IsExternal()) {
		routerStr = "External Router " + router.Kind() + ": " + router.Name() + "\n"
	}
	routerFiltersHeader := routerStr + rules.getFilterEffectStr(c, needEgress, needIngress)
	rulesStr = rules.getRuleDetailsStr(c, verbose, needEgress, needIngress)
	if connQuery == nil {
		noConnection = fmt.Sprintf("No connection between %v and %v;", src.Name(), dst.Name())
	} else {
		noConnection = fmt.Sprintf("There is no connection \"%v\" between %v and %v;", connQuery.String(), src.Name(), dst.Name())
	}
	switch {
	case router == nil && src.IsExternal():
		resStr += fmt.Sprintf("%v no fip router and src is external (fip is required for "+
			"outbound external connection)\n", noConnection)
	case router == nil && dst.IsExternal():
		resStr += fmt.Sprintf("%v no router (fip/pgw) and dst is external\n", noConnection)
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

func (rules *rulesConnection) getFilterEffectStr(c *VPCConfig, needEgress, needIngress bool) string {
	egressRulesStr := rules.egressRules.string(c, false, false)
	ingressRulesStr := rules.ingressRules.string(c, true, false)
	if needEgress && egressRulesStr != "" {
		egressRulesStr = "Egress: " + egressRulesStr
	}
	if needIngress && ingressRulesStr != "" {
		ingressRulesStr = "Ingres: " + ingressRulesStr
	}
	if egressRulesStr != "" && ingressRulesStr != "" {
		return egressRulesStr + "\n" + ingressRulesStr
	}
	return egressRulesStr + ingressRulesStr
}

func (rules *rulesConnection) getRuleDetailsStr(c *VPCConfig, verbose, needEgress, needIngress bool) string {
	if !verbose {
		return ""
	}
	egressRulesStr := rules.egressRules.string(c, false, true)
	ingressRulesStr := rules.ingressRules.string(c, true, true)
	if needEgress && egressRulesStr != "" {
		egressRulesStr = "Egress:\n" + egressRulesStr
	}
	if needIngress && ingressRulesStr != "" {
		ingressRulesStr = "Ingress:\n" + ingressRulesStr
	}
	if egressRulesStr != "" || ingressRulesStr != "" {
		return "\nRules details:\n~~~~~~~~~~~~~~\n" + egressRulesStr + ingressRulesStr
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
		resStr = fmt.Sprintf("Connection %v exists between %v and %v\n", conn.String(),
			src.Name(), dst.Name())
	}
	resStr += filtersEffectStr + "\n" + rulesStr
	return resStr
}

// prints either rulesDetails by calling StringDetailsRulesOfFilter or effect of each filter by calling StringFilterEffect
func (rulesInLayers rulesInLayers) string(c *VPCConfig, isIngress, rulesDetails bool) string {
	rulesInLayersStr := ""
	// order of presentation should be same as order of evaluation:
	// (1) the SGs attached to the src NIF (2) the outbound rules in the ACL attached to the src NIF's subnet
	// (3) the inbound rules in the ACL attached to the dst NIF's subnet (4) the SGs attached to the dst NIF.
	// thus, egress: security group first, ingress: nacl first
	filterLayersOrder := [2]string{SecurityGroupLayer, NaclLayer}
	if isIngress {
		filterLayersOrder = [2]string{NaclLayer, SecurityGroupLayer}
	}
	if isIngress {
		filterLayersOrder[0] = NaclLayer
		filterLayersOrder[1] = SecurityGroupLayer
	}
	for _, layer := range filterLayersOrder {
		filter := c.getFilterTrafficResourceOfKind(layer)
		if filter == nil {
			continue
		}
		if rules, ok := rulesInLayers[layer]; ok {
			if rulesDetails {
				rulesInLayersStr += filter.StringDetailsRulesOfFilter(rules)
			} else {
				thisFilterEffectString := filter.StringFilterEffect(rules)
				if rulesInLayersStr != "" && thisFilterEffectString != "" {
					rulesInLayersStr += semicolon + " "
				}
				rulesInLayersStr += filter.StringFilterEffect(rules)
			}
		}
	}
	return rulesInLayersStr
}
