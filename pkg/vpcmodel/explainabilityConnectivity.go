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
type rulesInLayers map[string][]RulesInFilter

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
	conn           *connection.Set
	externalRouter RoutingResource // the router (fip or pgw) to external network; nil if none or not relevant
	crossVpcRouter RoutingResource // the (currently only tgw) router between src and dst from different VPCs; nil if none or not relevant
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

func (configsMap MultipleVPCConfigs) ExplainConnectivity(src, dst string, connQuery *connection.Set) (res *Explanation, err error) {
	vpcConfig, srcNodes, dstNodes, isSrcDstInternalIP, err := configsMap.getVPCConfigAndSrcDstNodes(src, dst)
	if err != nil {
		return nil, err
	}
	return vpcConfig.explainConnectivityForVPC(src, dst, srcNodes, dstNodes, isSrcDstInternalIP, connQuery)
}

// explainConnectivityForVPC for a vpcConfig, given src, dst and connQuery returns a struct with all explanation details
// nil connQuery means connection is not part of the query
func (c *VPCConfig) explainConnectivityForVPC(src, dst string, srcNodes, dstNodes []Node, isSrcDstInternalIP srcDstInternalAddr,
	connQuery *connection.Set) (res *Explanation, err error) {
	// we do not support multiple configs, yet
	rulesAndDetails, err1 := c.computeExplainRules(srcNodes, dstNodes, connQuery)
	if err1 != nil {
		return nil, err1
	}
	// finds connEnabled and the existing connection between src and dst if connQuery nil,
	// otherwise the part of the connection intersecting connQuery
	err2 := rulesAndDetails.computeConnections(c, connQuery)
	if err2 != nil {
		return nil, err2
	}
	err3 := rulesAndDetails.computeRoutersAndFilters(c)
	if err3 != nil {
		return nil, err3
	}
	rulesAndDetails.computeActualRules()
	rulesAndDetails.computeCombinedActualRules() // combined deny and allow

	groupedLines, err4 := newGroupConnExplainability(c, &rulesAndDetails)
	if err4 != nil {
		return nil, err4
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
			rulesThisSrcDst := &srcDstDetails{src, dst, false, false, false,
				connection.None(), nil, nil, nil, allowRules,
				nil, denyRules, nil, nil}
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
func filterHasRelevantRules(rulesInFilter []RulesInFilter) bool {
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
		allowForLayer, ok1 := allow[layer]
		denyForLayer, ok2 := deny[layer]
		switch {
		case ok1 && ok2:
			// do nothing (merge will be right after the switch)
		case ok1: // layer relevant only for allow
			allowDenyMerged[layer] = allowForLayer
			continue
		case ok2: // layer relevant only for deny
			allowDenyMerged[layer] = denyForLayer
			continue
		default: // no rules in this layer
			continue
		}
		mergedRulesInLayer := []RulesInFilter{} // both deny and allow in layer
		// gets all indexes, both allow and deny, of a layer (e.g. indexes of nacls)
		allIndexes := getAllIndexesForFilter(allowForLayer, denyForLayer)
		// translates []RulesInFilter to a map for access efficiency
		allowRulesMap := rulesInLayerToMap(allowForLayer)
		denyRulesMap := rulesInLayerToMap(denyForLayer)
		for filterIndex := range allIndexes {
			allowRules := allowRulesMap[filterIndex]
			denyRules := denyRulesMap[filterIndex]
			// only one of them can be nil if we got here
			switch {
			case denyRules == nil:
				mergedRulesInLayer = append(mergedRulesInLayer, *allowRules)
			case allowRules == nil:
				mergedRulesInLayer = append(mergedRulesInLayer, *denyRules)
			default: // none nil, merge
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
				mergedRulesInFilter := RulesInFilter{Filter: filterIndex, Rules: mergedRules, RulesFilterType: rType}
				mergedRulesInLayer = append(mergedRulesInLayer, mergedRulesInFilter)
			}
		}
		allowDenyMerged[layer] = mergedRulesInLayer
	}
	return allowDenyMerged
}

type intSet = common.GenericSet[int]

// allow and deny in layer: gets all indexes of a layer (e.g. indexes of nacls)
func getAllIndexesForFilter(allowForLayer, denyForLayer []RulesInFilter) (indexes intSet) {
	indexes = intSet{}
	addIndexesOfFilters(indexes, allowForLayer)
	addIndexesOfFilters(indexes, denyForLayer)
	return indexes
}

// translates rulesInLayer into a map from filter's index to the rules indexes
func rulesInLayerToMap(rulesInLayer []RulesInFilter) map[int]*RulesInFilter {
	mapFilterRules := map[int]*RulesInFilter{}
	for _, rulesInFilter := range rulesInLayer {
		thisRulesInFilter := rulesInFilter // to make lint happy
		// do not reference an address of a loop value
		mapFilterRules[rulesInFilter.Filter] = &thisRulesInFilter
	}
	return mapFilterRules
}

func addIndexesOfFilters(indexes intSet, rulesInLayer []RulesInFilter) {
	for _, rulesInFilter := range rulesInLayer {
		indexes[rulesInFilter.Filter] = true
	}
}

func (c *VPCConfig) getFiltersRulesBetweenNodesPerDirectionAndLayer(
	src, dst Node, conn *connection.Set, isIngress bool, layer string) (allowRules *[]RulesInFilter,
	denyRules *[]RulesInFilter, err error) {
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

func (rulesInLayers rulesInLayers) updateRulesPerLayerIfNonEmpty(layer string, rulesFilter *[]RulesInFilter) {
	if len(*rulesFilter) > 0 {
		rulesInLayers[layer] = *rulesFilter
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
func (details *rulesAndConnDetails) computeConnections(c *VPCConfig, connQuery *connection.Set) error {
	connectivity, err := c.GetVPCNetworkConnectivity(false) // computes connectivity
	if err != nil {
		return err
	}
	for _, srcDstDetails := range *details {
		conn, err := connectivity.getConnection(c, srcDstDetails.src, srcDstDetails.dst)
		if err != nil {
			return err
		}
		if connQuery != nil { // connection is part of the query
			srcDstDetails.conn = conn.Intersect(connQuery)
		} else {
			srcDstDetails.conn = conn
		}
		srcDstDetails.connEnabled = !srcDstDetails.conn.IsEmpty()
	}
	return nil
}

// given that there is a connection between src to dst, gets it
// if src or dst is a node then the node is from getCidrExternalNodes,
// thus there is a node in VPCConfig that either equal to or contains it.
func (v *VPCConnectivity) getConnection(c *VPCConfig, src, dst Node) (conn *connection.Set, err error) {
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
	srcMapValue, ok := v.AllowedConnsCombined[srcForConnection]
	if ok {
		conn, ok = srcMapValue[dstForConnection]
	}
	if !ok {
		return nil, fmt.Errorf("error: there is a connection between %v and %v, but connection computation failed",
			srcForConnection.Name(), dstForConnection.Name())
	}
	return conn, nil
}
