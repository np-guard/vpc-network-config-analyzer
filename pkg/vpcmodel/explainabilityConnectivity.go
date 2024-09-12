/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
	"slices"

	"github.com/np-guard/models/pkg/connection"
)

var FilterLayers = [2]string{SecurityGroupLayer, NaclLayer}

const ResourceTypeIKSNode = "IKSNodeNetworkInterface"

// rulesInLayers contains specific rules across all layers (SGLayer/NACLLayer)
// it maps from the layer name to the list of rules
type rulesInLayers map[string][]RulesInTable

// rulesConnection contains the rules enabling a connection
type rulesConnection struct {
	ingressRules rulesInLayers
	egressRules  rulesInLayers
}

type srcDstDetails struct {
	src         Node
	dst         Node
	connEnabled bool
	// note that if dst/src is external then egressEnabled/ingressEnabled may be false and yet connEnabled true
	ingressEnabled bool
	egressEnabled  bool
	// the connection between src to dst, in case the connection was not part of the query;
	// the part of the connection relevant to the query otherwise.
	conn           *detailedConn
	externalRouter RoutingResource // the router (fip or pgw) to external network; nil if none or not relevant
	crossVpcRouter RoutingResource // the (currently only tgw) router between src and dst from different VPCs; nil if none or not relevant
	crossVpcRules  []RulesInTable  // cross vpc (only tgw at the moment) prefix rules effecting the connection (or lack of)
	// there could be more than one connection effecting the connection since src/dst cidr's may contain more than one AP

	// loadBalancerRule - the lb rule affecting this connection, nil if irrelevant (no LB).
	loadBalancerRule LoadBalancerRule
	// privateSubnetRule - rule of the private subnet affecting this connection, nil if irrelevant (no external src/dst).
	privateSubnetRule PrivateSubnetRule
	// filters relevant for this src, dst pair; map keys are the filters kind (NaclLayer/SecurityGroupLayer)
	// for two internal nodes within same subnet, only SG layer is relevant
	filtersRelevant     map[string]bool
	potentialAllowRules *rulesConnection // potentially enabling connection - potential given the filter is relevant
	actualAllowRules    *rulesConnection // enabling rules affecting connection given externalRouter; e.g. NACL is irrelevant if same subnet
	potentialDenyRules  *rulesConnection // deny rules potentially (w.r.t. externalRouter) effecting the connection, relevant for NACL
	actualDenyRules     *rulesConnection // deny rules effecting the connection, relevant for NACL
	actualMergedRules   *rulesConnection // rules actually effecting the connection (both allow and deny)
	// enabling rules implies whether ingress/egress is enabled
	// potential rules are saved for further debugging and explanation provided to the user
	respondRules         *rulesConnection // rules of non-stateful filters enabling/disabling respond
	crossVpcRespondRules []RulesInTable   // cross vpc (only tgw at the moment) prefix rules effecting the
	// TCP respond connection (or lack of)

}

type rulesAndConnDetails []*srcDstDetails

func NewExplanationArgs(src, dst, protocol string, srcMinPort, srcMaxPort, dstMinPort, dstMaxPort int64, detail bool) *ExplanationArgs {
	return &ExplanationArgs{src: src, dst: dst, protocol: protocol,
		srcMinPort: srcMinPort, srcMaxPort: srcMaxPort, dstMinPort: dstMinPort, dstMaxPort: dstMaxPort, detail: detail}
}

type Explanation struct {
	c               *VPCConfig
	connQuery       *connection.Set
	rulesAndDetails *rulesAndConnDetails // rules and more details for a single src->dst
	src             string
	dst             string
	srcNodes        []Node
	dstNodes        []Node
	// (Current) Analysis of the connectivity of cluster worker nodes is under the assumption that the only security
	// groups applied to them are the VPC default and the IKS generated SG; this comment needs to be added if src or dst is an IKS node
	hasIksNode bool
	// grouped connectivity result:
	// grouping common explanation lines with common src/dst (internal node) and different dst/src (external node)
	// [required due to computation with disjoint ip-blocks]
	groupedLines    []*groupedConnLine
	allRulesDetails *rulesDetails // all rules of the VPCConfig with details; used by printing functionality
}

// ExplainConnectivity returns Explanation object, that explains connectivity of a single <src, dst> couple given by the user
func (c *MultipleVPCConfigs) ExplainConnectivity(src, dst string, connQuery *connection.Set) (res *Explanation, err error) {
	vpcConfig, srcNodes, dstNodes, err := c.getVPCConfigAndSrcDstNodes(src, dst)
	if err != nil {
		return nil, err
	}
	if vpcConfig == nil {
		// No error and also no matching vpc config for both src and dst: missing cross-vpc router.
		// No VPCConfig to work with in this case, thus, this case is treated separately
		return &Explanation{connQuery: connQuery, src: src, dst: dst, srcNodes: srcNodes, dstNodes: dstNodes}, nil
	}
	connectivity, err1 := vpcConfig.GetVPCNetworkConnectivity(false, false) // computes connectivity
	if err1 != nil {
		return nil, err1
	}
	return vpcConfig.explainConnectivityForVPC(src, dst, srcNodes, dstNodes, connQuery, connectivity)
}

// explainConnectivityForVPC for a vpcConfig, given src, dst and connQuery returns a struct with all explanation details
// nil connQuery means connection is not part of the query
func (c *VPCConfig) explainConnectivityForVPC(src, dst string, srcNodes, dstNodes []Node,
	connQuery *connection.Set, connectivity *VPCConnectivity) (res *Explanation, err error) {
	// we do not support multiple configs, yet
	rulesAndDetails, err1 := c.computeExplainRules(srcNodes, dstNodes, connQuery)
	if err1 != nil {
		return nil, err1
	}
	// finds connEnabled and the existing connection between src and dst if connQuery nil,
	// otherwise the part of the connection intersecting connQuery
	err2 := rulesAndDetails.computeConnections(c, connQuery, connectivity)
	if err2 != nil {
		return nil, err2
	}
	err3 := rulesAndDetails.computeRoutersAndFilters(c)
	if err3 != nil {
		return nil, err3
	}
	rulesAndDetails.computeActualRules()
	rulesAndDetails.computeCombinedActualRules() // combined deny and allow
	err4 := rulesAndDetails.updateRespondRules(c, connQuery)
	if err4 != nil {
		return nil, err4
	}
	allRulesDetails, err5 := newRulesDetails(c)
	if err5 != nil {
		return nil, err5
	}
	groupedLines, err6 := newGroupConnExplainability(c, allRulesDetails, &rulesAndDetails)
	if err6 != nil {
		return nil, err6
	}
	// the user has to be notified regarding an assumption we make about IKSNode's security group
	hasIksNode := srcNodes[0].Kind() == ResourceTypeIKSNode || dstNodes[0].Kind() == ResourceTypeIKSNode
	// computes rulesDetails which contains a list of all rules of the VPCConfig; these are used by explain printing
	// functionality. we compute it here so that it is computed only once
	return &Explanation{c, connQuery, &rulesAndDetails, src, dst, srcNodes, dstNodes,
		hasIksNode, groupedLines.GroupedLines, allRulesDetails}, nil
}

// computeExplainRules computes the egress and ingress rules contributing to the (existing or missing) connection <src, dst>
func (c *VPCConfig) computeExplainRules(srcNodes, dstNodes []Node,
	conn *connection.Set) (rulesAndConn rulesAndConnDetails, err error) {
	// the size is not known in this stage due to the corner case in which we have the same node both in srcNodes and dstNodes
	rulesAndConn = rulesAndConnDetails{}
	for _, src := range srcNodes {
		for _, dst := range dstNodes {
			if src.UID() == dst.UID() {
				continue
			}
			allowRules, denyRules, err := c.getRulesOfConnection(src, dst, conn)
			if err != nil {
				return nil, err
			}
			rulesThisSrcDst := &srcDstDetails{src: src, dst: dst, conn: emptyDetailedConn(),
				potentialAllowRules: allowRules, potentialDenyRules: denyRules}
			rulesAndConn = append(rulesAndConn, rulesThisSrcDst)
		}
	}
	return rulesAndConn, nil
}

// computeRoutersAndFilters computes for each  <src, dst> :
// 1. The tgw routingResource, if exists
// 2. The load balancer rule
// 3. The external routingResource, if exists
// Note that at most one of the routingResource exists for any <src, dst>
// 4. The external filters relevant to the <src, dst> given the external routingResource
// 5. The internal filters relevant to the <src, dst>
// 6. The actual relevant filter, depending on whether src xor dst is external
func (details *rulesAndConnDetails) computeRoutersAndFilters(c *VPCConfig) (err error) {
	for _, singleSrcDstDetails := range *details {
		// RoutingResources are computed by the parser for []Nodes of the VPC,
		src := singleSrcDstDetails.src
		dst := singleSrcDstDetails.dst
		singleSrcDstDetails.loadBalancerRule = c.getLoadBalancerRule(src, dst)
		singleSrcDstDetails.privateSubnetRule = c.getPrivateSubnetRule(src, dst)
		if src.IsInternal() && dst.IsInternal() { // internal (including cross vpcs)
			singleSrcDstDetails.crossVpcRouter, _, err = c.getRoutingResource(src, dst)
			if err != nil {
				return err
			}
			if singleSrcDstDetails.crossVpcRouter != nil {
				singleSrcDstDetails.crossVpcRules = singleSrcDstDetails.crossVpcRouter.RulesInConnectivity(src, dst)
			}
			singleSrcDstDetails.filtersRelevant = src.(InternalNodeIntf).AppliedFiltersKinds(dst.(InternalNodeIntf))
		} else { // external
			singleSrcDstDetails.filtersRelevant = map[string]bool{NaclLayer: true, SecurityGroupLayer: true}
			externalRouter, _, err := c.getRoutingResource(src, dst)
			if err != nil {
				return err
			}
			if externalRouter == nil {
				continue // no externalRouter: no connections
			}
			singleSrcDstDetails.externalRouter = externalRouter
		}
	}
	return nil
}

// computeActualRules computes, after potentialRules and filters were computed, for each  <src, dst> :
// 1. from the potentialRules the actualRules (per ingress, egress) that actually enable traffic,
// considering filtersRelevant which, depending on src and dst is either derived from
// filtersExternal - which was computed based on the RoutingResource - and removing filters
// not relevant for the Router e.g. nacl not relevant fip
// or was derived from filterInternal - removing nacl when both vsis are of the same subnets
// 2. ingressEnabled and egressEnabled: whether traffic is enabled via ingress, egress
func (details *rulesAndConnDetails) computeActualRules() {
	for _, singleSrcDstDetails := range *details {
		filterRelevant := singleSrcDstDetails.filtersRelevant
		actualAllowIngress, ingressEnabled :=
			computeActualRulesGivenRulesFilter(singleSrcDstDetails.potentialAllowRules.ingressRules, filterRelevant)
		// ingress disabled due to private subnet?
		privateSubnetRule := singleSrcDstDetails.privateSubnetRule
		ingressEnabled = ingressEnabled && (privateSubnetRule == nil || !privateSubnetRule.Deny(true))
		actualAllowEgress, egressEnabled :=
			computeActualRulesGivenRulesFilter(singleSrcDstDetails.potentialAllowRules.egressRules, filterRelevant)
		egressEnabled = egressEnabled && (privateSubnetRule == nil || !privateSubnetRule.Deny(false))
		actualDenyIngress, _ := computeActualRulesGivenRulesFilter(singleSrcDstDetails.potentialDenyRules.ingressRules, filterRelevant)
		actualDenyEgress, _ := computeActualRulesGivenRulesFilter(singleSrcDstDetails.potentialDenyRules.egressRules, filterRelevant)
		actualAllow := &rulesConnection{*actualAllowIngress, *actualAllowEgress}
		actualDeny := &rulesConnection{*actualDenyIngress, *actualDenyEgress}
		singleSrcDstDetails.actualAllowRules = actualAllow
		singleSrcDstDetails.ingressEnabled = ingressEnabled
		singleSrcDstDetails.egressEnabled = egressEnabled
		singleSrcDstDetails.actualDenyRules = actualDeny
	}
}

// given rulesInLayers and the relevant filters, computes actual rules and whether the direction is enabled,
// given that rulesInLayers are allow rules; for deny rules this computation is meaningless and is ignored.
// this is called separately for each direction (ingress/egress) and allow/deny
func computeActualRulesGivenRulesFilter(rulesLayers rulesInLayers, filters map[string]bool) (*rulesInLayers, bool) {
	actualRules := rulesInLayers{}
	directionEnabled := true
	for _, layer := range FilterLayers {
		filterIsRelevant := filters[layer]
		potentialRules := rulesLayers[layer]
		// The filter is blocking if it is relevant and has no allow rules
		// this computation is meaningful only when rulesLayers are allow rules and is ignored otherwise
		if filterIsRelevant && !filterHasRelevantRules(potentialRules) {
			directionEnabled = false
		}
		if filterIsRelevant {
			actualRules[layer] = potentialRules
		}
	}
	// the direction is enabled if none of the filters is blocking it
	return &actualRules, directionEnabled
}

// returns true if filter contains rules
func filterHasRelevantRules(rulesInFilter []RulesInTable) bool {
	for _, rulesFilter := range rulesInFilter {
		if len(rulesFilter.Rules) > 0 {
			return true
		}
	}
	return false
}

// computes combined list of rules, both deny and allow
func (details *rulesAndConnDetails) computeCombinedActualRules() {
	for _, singleSrcDstDetails := range *details {
		actualRulesIngress := mergeAllowDeny(singleSrcDstDetails.actualAllowRules.ingressRules,
			singleSrcDstDetails.actualDenyRules.ingressRules)
		actualRulesEgress := mergeAllowDeny(singleSrcDstDetails.actualAllowRules.egressRules,
			singleSrcDstDetails.actualDenyRules.egressRules)
		actualRules := &rulesConnection{actualRulesIngress, actualRulesEgress}
		singleSrcDstDetails.actualMergedRules = actualRules
	}
}

// merges two rulesInLayers - for merging deny and allow for ingress and egress
func mergeAllowDeny(allow, deny rulesInLayers) rulesInLayers {
	allowDenyMerged := rulesInLayers{}
	for _, layer := range FilterLayers {
		allowForLayer := allow[layer]
		denyForLayer := deny[layer]
		actualAllow := len(allowForLayer) > 0
		actualDeny := len(denyForLayer) > 0
		switch {
		case actualAllow && actualDeny:
			// do nothing (merge will be right after the switch)
		case actualAllow: // layer relevant only for allow
			allowDenyMerged[layer] = allowForLayer
			continue
		case actualDeny: // layer relevant only for deny
			allowDenyMerged[layer] = denyForLayer
			continue
		default: // no rules in this layer
			continue
		}
		// both deny and allow rules in layer, namely, the layer is NaclLayer. There is a single nacl per subnet.
		// Thus, if we got here the layer has a single table in it with both allow and deny rules.
		// Namely, allowForLayer and denyForLayer each have a single element originating from the same table
		allowRules := allowForLayer[0]
		denyRules := denyForLayer[0]
		mergedRules := []int{}
		// todo: once we update to go.1.22 use slices.Concat
		mergedRules = append(mergedRules, allowRules.Rules...)
		mergedRules = append(mergedRules, denyRules.Rules...)
		slices.Sort(mergedRules)
		var rType RulesType
		switch {
		case len(allowRules.Rules) > 0 && len(denyRules.Rules) > 0:
			rType = BothAllowDeny
		case len(allowRules.Rules) > 0:
			rType = OnlyAllow
		case len(denyRules.Rules) > 0:
			rType = OnlyDeny
		default: // no rules
			rType = NoRules
		}
		filterIndex := allowRules.TableIndex // can be taken either from allowForLayer or from denyForLayer
		mergedRulesInFilter := RulesInTable{TableIndex: filterIndex, Rules: mergedRules, RulesOfType: rType,
			TableHasEffect: allowRules.TableHasEffect} // TableHasEffect can be taken from either allow or deny
		allowDenyMerged[layer] = []RulesInTable{mergedRulesInFilter}
	}
	return allowDenyMerged
}

func (c *VPCConfig) getFiltersRulesBetweenNodesPerDirectionAndLayer(
	src, dst Node, conn *connection.Set, isIngress bool, layer string) (allowRules *[]RulesInTable,
	denyRules *[]RulesInTable, err error) {
	filter := c.GetFilterTrafficResourceOfKind(layer)
	if filter == nil {
		return nil, nil, fmt.Errorf("layer %v not found in configuration", layer)
	}
	rulesOfFilter, denyRulesOfFilter, err := filter.RulesInConnectivity(src, dst, conn, isIngress)
	if err != nil {
		return nil, nil, err
	}
	return &rulesOfFilter, &denyRulesOfFilter, nil
}

func (c *VPCConfig) getRulesOfConnection(src, dst Node,
	conn *connection.Set) (allowRulesOfConnection, denyRulesOfConnection *rulesConnection, err error) {
	ingressAllowPerLayer, egressAllowPerLayer := rulesInLayers{}, rulesInLayers{}
	ingressDenyPerLayer, egressDenyPerLayer := rulesInLayers{}, rulesInLayers{}
	for _, layer := range FilterLayers {
		// ingress rules: relevant only if dst is internal
		if dst.IsInternal() {
			ingressAllowRules, ingressDenyRules, err1 := c.getFiltersRulesBetweenNodesPerDirectionAndLayer(src, dst, conn, true, layer)
			if err1 != nil {
				return nil, nil, err1
			}
			ingressAllowPerLayer.updateRulesPerLayerIfNonEmpty(layer, ingressAllowRules)
			ingressDenyPerLayer.updateRulesPerLayerIfNonEmpty(layer, ingressDenyRules)
		}

		// egress rules: relevant only is src is internal
		if src.IsInternal() {
			egressAllowRules, egressDenyRules, err2 := c.getFiltersRulesBetweenNodesPerDirectionAndLayer(src, dst, conn, false, layer)
			if err2 != nil {
				return nil, nil, err2
			}
			egressAllowPerLayer.updateRulesPerLayerIfNonEmpty(layer, egressAllowRules)
			egressDenyPerLayer.updateRulesPerLayerIfNonEmpty(layer, egressDenyRules)
		}
	}
	allowRulesOfConnection = &rulesConnection{ingressRules: ingressAllowPerLayer, egressRules: egressAllowPerLayer}
	denyRulesOfConnection = &rulesConnection{ingressRules: ingressDenyPerLayer, egressRules: egressDenyPerLayer}
	return allowRulesOfConnection, denyRulesOfConnection, nil
}

func (rules rulesInLayers) updateRulesPerLayerIfNonEmpty(layer string, rulesFilter *[]RulesInTable) {
	if len(*rulesFilter) > 0 {
		rules[layer] = *rulesFilter
	}
}

// given a node, we need to find the resource that represent the node in the connectivity
func (c *VPCConfig) getConnectedResource(node Node) (VPCResourceIntf, error) {
	if AbstractedToNodeSet := node.AbstractedToNodeSet(); AbstractedToNodeSet != nil {
		// if the node is part of abstraction - return the abstracted nodeSet:
		return AbstractedToNodeSet, nil
	} else if node.IsInternal() {
		return node, nil
	}
	return c.getContainingConfigNode(node)
}

// node is from getCidrExternalNodes, thus there is a node in VPCConfig that either equal to or contains it.
func (c *VPCConfig) getContainingConfigNode(node Node) (Node, error) {
	nodeIPBlock := node.IPBlock()
	if nodeIPBlock == nil { // string cidr does not represent a legal cidr, would be handled earlier
		return nil, fmt.Errorf("node %v does not refer to a legal IP", node.Name())
	}
	for _, configNode := range c.Nodes {
		if configNode.IsInternal() {
			continue
		}
		configNodeIPBlock := configNode.IPBlock()
		if nodeIPBlock.ContainedIn(configNodeIPBlock) {
			return configNode, nil
		}
	}
	// todo: at the moment gets here for certain internal addresses not connected to vsi.
	//       should be handled as part of the https://github.com/np-guard/vpc-network-config-analyzer/issues/305
	//       verify internal addresses gets her - open a issue if this is the case
	return nil, nil
}

// computeConnections computes connEnabled and the relevant connection between src and dst
// if conn not specified in the query then the entire existing connection is relevant;
// if conn specified in the query then the relevant connection is their intersection
// todo: connectivity is computed for the entire network, even though we need only for specific src, dst pairs
// this is seems the time spent here should be neglectable, not worth the effort of adding dedicated code
func (details *rulesAndConnDetails) computeConnections(c *VPCConfig,
	connQuery *connection.Set, connectivity *VPCConnectivity) (err error) {
	for _, srcDstDetails := range *details {
		conn, err := connectivity.getConnection(c, srcDstDetails.src, srcDstDetails.dst)
		if err != nil {
			return err
		}
		if connQuery != nil { // connection is part of the query
			srcDstDetails.conn = newDetailedConn(conn.tcpRspEnable.Intersect(connQuery),
				conn.nonTCP.Intersect(connQuery), conn.allConn.Intersect(connQuery))
		} else {
			srcDstDetails.conn = conn
		}
		srcDstDetails.connEnabled = !srcDstDetails.conn.isEmpty()
	}
	return nil
}

// given that there is a connection between src to dst, gets it
// if src or dst is a node then the node is from getCidrExternalNodes,
// thus there is a node in VPCConfig that either equal to or contains it.
func (v *VPCConnectivity) getConnection(c *VPCConfig, src, dst Node) (conn *detailedConn, err error) {
	srcForConnection, err1 := c.getConnectedResource(src)
	if err1 != nil {
		return nil, err1
	}
	errMsg := "could not find containing config node for %v"
	if srcForConnection == nil {
		return nil, fmt.Errorf(errMsg, src.Name())
	}
	dstForConnection, err2 := c.getConnectedResource(dst)
	if err2 != nil {
		return nil, err2
	}
	if dstForConnection == nil {
		return nil, fmt.Errorf(errMsg, dst.Name())
	}
	var ok bool
	srcMapValue, ok := v.AllowedConnsCombinedResponsive[srcForConnection]
	if ok {
		conn, ok = srcMapValue[dstForConnection]
	}
	if !ok {
		return nil, fmt.Errorf("error: there is a connection between %v and %v, but connection computation failed",
			srcForConnection.Name(), dstForConnection.Name())
	}
	return conn, nil
}

// updates respondRules of each line in rulesAndConnDetails
// respondRules are the rules enabling/disabling the response when relevant:
// respond is relevant for TCP, and respond rules are relevant when non-stateful filters are relevant (NACL)
func (details *rulesAndConnDetails) updateRespondRules(c *VPCConfig, connQuery *connection.Set) error {
	responseConn := allTCPconn()
	if connQuery != nil {
		responseConn = responseConn.Intersect(connQuery)
	}
	for _, srcDstDetails := range *details {
		// respond rules are relevant if connection has a TCP component and (non-stateful filter (NACL at the moment)
		// are relevant for <src, dst> or there is a cross vpc router (tgw at the moment))
		if !respondRulesRelevant(srcDstDetails.conn, srcDstDetails.filtersRelevant, srcDstDetails.crossVpcRouter) {
			continue
		}
		// non-stateful filters (NACL at the moment) - gather filter rules relevant to TCP respond
		if srcDstDetails.filtersRelevant[statelessLayerName] {
			respondRules, err := c.getRespondRules(srcDstDetails.src, srcDstDetails.dst, responseConn)
			if err != nil {
				return err
			}
			srcDstDetails.respondRules = respondRules
		}
		// crossVPC based connection - gather router rules' relevant to TCP respond
		if srcDstDetails.crossVpcRouter != nil {
			srcDstDetails.crossVpcRespondRules = srcDstDetails.crossVpcRouter.RulesInConnectivity(srcDstDetails.dst,
				srcDstDetails.src)
		}
	}
	return nil
}

func respondRulesRelevant(conn *detailedConn, filtersRelevant map[string]bool, crossVPCRouter RoutingResource) bool {
	return conn.hasTCPComponent() && (filtersRelevant[statelessLayerName] || crossVPCRouter != nil)
}

// gets the NACL rules that enables/disables respond for connection conn, assuming nacl is applied
func (c *VPCConfig) getRespondRules(src, dst Node,
	conn *connection.Set) (respondRules *rulesConnection, err error) {
	mergedIngressRules, mergedEgressRules := rulesInLayers{}, rulesInLayers{}
	// respond: from dst to src; thus, ingress rules: relevant only if *src* is internal, egress is *dst* is internal
	if src.IsInternal() {
		var err error
		mergedIngressRules, err = c.computeAndUpdateDirectionRespondRules(src, dst, conn, true)
		if err != nil {
			return nil, err
		}
	}
	if dst.IsInternal() {
		var err error
		mergedEgressRules, err = c.computeAndUpdateDirectionRespondRules(src, dst, conn, false)
		if err != nil {
			return nil, err
		}
	}
	return &rulesConnection{mergedIngressRules, mergedEgressRules}, nil
}

func (c *VPCConfig) computeAndUpdateDirectionRespondRules(src, dst Node, conn *connection.Set,
	isIngress bool) (rulesInLayers, error) {
	// respond: dst and src switched, src and dst ports also switched
	// computes allowRulesPerLayer/denyRulePerLayer: ingress/egress rules enabling/disabling respond
	// note that there could be both allow and deny in case part of the connection is enabled and part blocked
	connSwitch := conn.SwitchSrcDstPorts()
	allowRules, denyRules, err1 := c.getFiltersRulesBetweenNodesPerDirectionAndLayer(dst, src, connSwitch, isIngress,
		statelessLayerName)
	if err1 != nil {
		return nil, err1
	}
	allowRulesPerLayer, denyRulePerLayer := rulesInLayers{}, rulesInLayers{}
	allowRulesPerLayer.updateRulesPerLayerIfNonEmpty(statelessLayerName, allowRules)
	denyRulePerLayer.updateRulesPerLayerIfNonEmpty(statelessLayerName, denyRules)
	mergedRules := mergeAllowDeny(allowRulesPerLayer, denyRulePerLayer)
	return mergedRules, err1
}
