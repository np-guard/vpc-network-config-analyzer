/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vpcmodel

import (
	"fmt"
	"slices"

	"github.com/np-guard/models/pkg/connection"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

var filterLayers = [2]string{SecurityGroupLayer, NaclLayer}

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

	// filters relevant for this src, dst pair; map keys are the filters kind (NaclLayer/SecurityGroupLayer)
	// for two internal nodes within same subnet, only SG layer is relevant
	// for external connectivity (src/dst is external) with FIP, only SG layer is relevant
	filtersRelevant     map[string]bool
	potentialAllowRules *rulesConnection // potentially enabling connection - potential given the filter is relevant
	actualAllowRules    *rulesConnection // enabling rules effecting connection given externalRouter; e.g. NACL is not relevant for fip
	potentialDenyRules  *rulesConnection // deny rules potentially (w.r.t. externalRouter) effecting the connection, relevant for ACL
	actualDenyRules     *rulesConnection // deny rules effecting the connection, relevant for ACL
	actualMergedRules   *rulesConnection // rules actually effecting the connection (both allow and deny)
	// enabling rules implies whether ingress/egress is enabled
	// potential rules are saved for further debugging and explanation provided to the user
	respondRules *rulesConnection // rules of non-stateful filters enabling/disabling respond

}

type rulesAndConnDetails []*srcDstDetails

func NewExplanationArgs(src, dst, protocol string, srcMinPort, srcMaxPort, dstMinPort, dstMaxPort int64) *ExplanationArgs {
	return &ExplanationArgs{src: src, dst: dst, protocol: protocol,
		srcMinPort: srcMinPort, srcMaxPort: srcMaxPort, dstMinPort: dstMinPort, dstMaxPort: dstMaxPort}
}

type Explanation struct {
	c               *VPCConfig
	connQuery       *connection.Set
	rulesAndDetails *rulesAndConnDetails // rules and more details for a single src->dst
	src             string
	dst             string
	// the following two properties are for the case src/dst are given as internal address connected to network interface
	// this information should be handy; otherwise empty (slice of size 0)
	srcNetworkInterfacesFromIP []Node
	dstNetworkInterfacesFromIP []Node
	// (Current) Analysis of the connectivity of cluster worker nodes is under the assumption that the only security
	// groups applied to them are the VPC default and the IKS generated SG; this comment needs to be added if src or dst is an IKS node
	hasIksNode bool
	// grouped connectivity result:
	// grouping common explanation lines with common src/dst (internal node) and different dst/src (external node)
	// [required due to computation with disjoint ip-blocks]
	groupedLines []*groupedConnLine
}

// ExplainConnectivity returns Explanation object, that explains connectivity of a single <src, dst> couple given by the user
func (c *MultipleVPCConfigs) ExplainConnectivity(src, dst string, connQuery *connection.Set) (res *Explanation, err error) {
	vpcConfig, srcNodes, dstNodes, isSrcDstInternalIP, err := c.getVPCConfigAndSrcDstNodes(src, dst)
	if err != nil {
		return nil, err
	}
	if vpcConfig == nil {
		// No error and also no matching vpc config for both src and dst: missing cross-vpc router.
		// No VPCConfig to work with in this case, thus, this case is treated separately
		return &Explanation{connQuery: connQuery, src: src, dst: dst}, nil
	}
	connectivity, err1 := vpcConfig.GetVPCNetworkConnectivity(false, false) // computes connectivity
	if err1 != nil {
		return nil, err1
	}
	return vpcConfig.explainConnectivityForVPC(src, dst, srcNodes, dstNodes, isSrcDstInternalIP, connQuery, connectivity)
}

// explainConnectivityForVPC for a vpcConfig, given src, dst and connQuery returns a struct with all explanation details
// nil connQuery means connection is not part of the query
func (c *VPCConfig) explainConnectivityForVPC(src, dst string, srcNodes, dstNodes []Node, isSrcDstInternalIP srcDstInternalAddr,
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

	groupedLines, err5 := newGroupConnExplainability(c, &rulesAndDetails)
	if err5 != nil {
		return nil, err5
	}
	// the user has to be notified regarding an assumption we make about IKSNode's security group
	hasIksNode := srcNodes[0].Kind() == ResourceTypeIKSNode || dstNodes[0].Kind() == ResourceTypeIKSNode
	return &Explanation{c, connQuery, &rulesAndDetails, src, dst,
		getNetworkInterfacesFromIP(isSrcDstInternalIP.src, srcNodes),
		getNetworkInterfacesFromIP(isSrcDstInternalIP.dst, dstNodes),
		hasIksNode, groupedLines.GroupedLines}, nil
}

func getNetworkInterfacesFromIP(isInputInternalIP bool, nodes []Node) []Node {
	if isInputInternalIP {
		return nodes
	}
	return []Node{}
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
// 2. The external routingResource, if exists
// Note that at most one of the routingResource exists for any <src, dst>
// 2. The external filters relevant to the <src, dst> given the external routingResource
// 3. The internal filters relevant to the <src, dst>
// 4. The actual relevant filter, depending on whether src xor dst is external
func (details *rulesAndConnDetails) computeRoutersAndFilters(c *VPCConfig) (err error) {
	for _, singleSrcDstDetails := range *details {
		// RoutingResources are computed by the parser for []Nodes of the VPC,
		src := singleSrcDstDetails.src
		dst := singleSrcDstDetails.dst
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
			externalRouter, _, err := c.getRoutingResource(src, dst)
			if err != nil {
				return err
			}
			if externalRouter == nil {
				continue // no externalRouter: no connections, filtersLayers non defined
			}
			singleSrcDstDetails.externalRouter = externalRouter
			singleSrcDstDetails.filtersRelevant = externalRouter.AppliedFiltersKinds() // relevant filtersExternal
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
		actualAllowEgress, egressEnabled :=
			computeActualRulesGivenRulesFilter(singleSrcDstDetails.potentialAllowRules.egressRules, filterRelevant)
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
	for _, layer := range filterLayers {
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
	for _, layer := range filterLayers {
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
		mergedRulesInLayer := []RulesInTable{} // both deny and allow in layer
		// gets all indexes, both allow and deny, of a layer (e.g. indexes of nacls)
		allIndexes := getAllIndexesForFilter(allowForLayer, denyForLayer)
		// translates []RulesInTable to a map for access efficiency
		allowRulesMap := rulesInLayerToMap(allowForLayer)
		denyRulesMap := rulesInLayerToMap(denyForLayer)
		for filterIndex := range allIndexes {
			allowRules := allowRulesMap[filterIndex]
			denyRules := denyRulesMap[filterIndex]
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
			mergedRulesInFilter := RulesInTable{Table: filterIndex, Rules: mergedRules, RulesOfType: rType}
			mergedRulesInLayer = append(mergedRulesInLayer, mergedRulesInFilter)
		}
		allowDenyMerged[layer] = mergedRulesInLayer
	}
	return allowDenyMerged
}

type intSet = common.GenericSet[int]

// allow and deny in layer: gets all indexes of a layer (e.g. indexes of nacls)
func getAllIndexesForFilter(allowForLayer, denyForLayer []RulesInTable) (indexes intSet) {
	indexes = intSet{}
	addIndexesOfFilters(indexes, allowForLayer)
	addIndexesOfFilters(indexes, denyForLayer)
	return indexes
}

// translates rulesInLayer into a map from filter's index to the rules indexes
func rulesInLayerToMap(rulesInLayer []RulesInTable) map[int]*RulesInTable {
	mapFilterRules := map[int]*RulesInTable{}
	for _, rulesInFilter := range rulesInLayer {
		thisRulesInFilter := rulesInFilter // to make lint happy
		// do not reference an address of a loop value
		mapFilterRules[rulesInFilter.Table] = &thisRulesInFilter
	}
	return mapFilterRules
}

func addIndexesOfFilters(indexes intSet, rulesInLayer []RulesInTable) {
	for _, rulesInFilter := range rulesInLayer {
		indexes[rulesInFilter.Table] = true
	}
}

func (c *VPCConfig) getFiltersRulesBetweenNodesPerDirectionAndLayer(
	src, dst Node, conn *connection.Set, isIngress bool, layer string) (allowRules *[]RulesInTable,
	denyRules *[]RulesInTable, err error) {
	filter := c.getFilterTrafficResourceOfKind(layer)
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
	for _, layer := range filterLayers {
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

// node is from getCidrExternalNodes, thus there is a node in VPCConfig that either equal to or contains it.
func (c *VPCConfig) getContainingConfigNode(node Node) (Node, error) {
	if node.IsInternal() { // node is not external - nothing to do
		return node, nil
	}
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
	srcForConnection, err1 := c.getContainingConfigNode(src)
	if err1 != nil {
		return nil, err1
	}
	errMsg := "could not find containing config node for %v"
	if srcForConnection == nil {
		return nil, fmt.Errorf(errMsg, src.Name())
	}
	dstForConnection, err2 := c.getContainingConfigNode(dst)
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

func (details *rulesAndConnDetails) updateRespondRules(c *VPCConfig, connQuery *connection.Set) error {
	for _, srcDstDetails := range *details {
		// respond rules are relevant if connection has a TCP component and non-stateful filter (NACL at the moment)
		// are relevant for <src, dst>
		if !respondRulesRelevant(srcDstDetails.conn, srcDstDetails.filtersRelevant) {
			continue
		}
		connForResp := newTCPSet()
		if connQuery != nil {
			connForResp = connForResp.Intersect(connQuery)
		}
		respondRules, err := c.getRespondRules(srcDstDetails.src, srcDstDetails.dst, connForResp)
		if err != nil {
			return err
		}
		srcDstDetails.respondRules = respondRules
	}
	return nil
}

func respondRulesRelevant(conn *detailedConn, filtersRelevant map[string]bool) bool {
	return conn.hasTCPComponent() && filtersRelevant[NaclLayer]
}

// gets the NACL rules that enables/disables respond for connection conn, assuming nacl is applied
func (c *VPCConfig) getRespondRules(src, dst Node,
	conn *connection.Set) (respondRules *rulesConnection, err error) {
	ingressAllowPerLayer, egressAllowPerLayer := rulesInLayers{}, rulesInLayers{}
	ingressDenyPerLayer, egressDenyPerLayer := rulesInLayers{}, rulesInLayers{}
	// todo: switch dst src ports of conn - to that end needs to merge the PR on connections that exports the func
	connSwitch := conn
	mergedIngressRules, mergedEgressRules := rulesInLayers{}, rulesInLayers{}
	// respond: from dst to src. Thus, ingress rules: relevant only if *src* is internal, egress is *dst* is internal
	if src.IsInternal() {
		// respond: dst and src switched
		ingressAllowRules, ingressDenyRules, err1 := c.getFiltersRulesBetweenNodesPerDirectionAndLayer(dst, src, connSwitch, true, NaclLayer)
		if err1 != nil {
			return nil, err1
		}
		ingressAllowPerLayer.updateRulesPerLayerIfNonEmpty(NaclLayer, ingressAllowRules)
		ingressDenyPerLayer.updateRulesPerLayerIfNonEmpty(NaclLayer, ingressDenyRules)
		mergedIngressRules = mergeAllowDeny(ingressAllowPerLayer, ingressDenyPerLayer)
	}
	if dst.IsInternal() {
		// respond: dst and src switched
		egressAllowRules, egressDenyRules, err2 := c.getFiltersRulesBetweenNodesPerDirectionAndLayer(dst, src, conn, false, NaclLayer)
		if err2 != nil {
			return nil, err2
		}
		egressAllowPerLayer.updateRulesPerLayerIfNonEmpty(NaclLayer, egressAllowRules)
		egressDenyPerLayer.updateRulesPerLayerIfNonEmpty(NaclLayer, egressDenyRules)
		mergedEgressRules = mergeAllowDeny(egressAllowPerLayer, egressDenyPerLayer)
	}
	return &rulesConnection{mergedIngressRules, mergedEgressRules}, nil
}
