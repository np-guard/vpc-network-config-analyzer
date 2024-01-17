package vpcmodel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

// rulesInLayers contains specific rules across all layers (SGLayer/NACLLayer)
// it maps from the layer name to the list of rules
type rulesInLayers map[string][]RulesInFilter

// rulesConnection contains the rules enabling a connection
type rulesConnection struct {
	ingressRules rulesInLayers
	egressRules  rulesInLayers
}

type rulesSingleSrcDst struct {
	src             Node
	dst             Node
	conn            *common.ConnectionSet
	router          RoutingResource // the router (fip or pgw) to external network; nil if none
	filtersExternal map[string]bool // filters relevant for external IP
	rules           *rulesConnection
}

type rulesAndConnDetails []*rulesSingleSrcDst

type explanation struct {
	c              *VPCConfig
	connQuery      *common.ConnectionSet
	potentialRules *rulesAndConnDetails // rules potentially enabling connection
	actualRules    *rulesAndConnDetails // rules enabling connection given router
	// at the moment (only SG) potentialRules may differ from actualRules only if src or dst is external
	// grouped connectivity result:
	// grouping common explanation lines with common src/dst (internal node) and different dst/src (external node)
	// [required due to computation with disjoint ip-blocks]
	groupedLines []*groupedConnLine
}

// finds the node of a given, by its name, Vsi
func (c *VPCConfig) getVsiNode(name string) Node {
	for _, node := range c.Nodes {
		// currently, supported: network interface given takes only that one.
		//  todo:   if address not given but only vsi name - take all network interfaces of that vsi
		if name == node.Name() {
			return node
		}
	}
	return nil
}

// given input cidr, gets (disjoint) external nodes I s.t.:
//  1. The union of these nodes is the cidr
//  2. Let i be a node in I and n be a node in VPCConfig.
//     i and n are either disjoint or i is contained in n
//     Note that the vpconfig nodes were chosen w.r.t. connectivity rules (SG and NACL)
//     s.t. each node either fully belongs to a rule or is disjoint to it.
//     to get nodes I as above:
//  1. Calculate the IP blocks of the nodes N
//  2. Calculate from N and the cidr block, disjoint IP blocks
//  3. Return the nodes created from each block from 2 contained in the input cidr
func (c *VPCConfig) getCidrExternalNodes(cidr string) (cidrNodes []Node, err error) {
	cidrsIPBlock := common.NewIPBlockFromCidr(cidr)
	if cidrsIPBlock == nil { // string cidr does not represent a legal cidr
		return nil, nil
	}
	// 1.
	vpcConfigNodesExternalBlock := []*common.IPBlock{}
	for _, node := range c.Nodes {
		if node.IsInternal() {
			continue
		}
		thisNodeBlock := common.NewIPBlockFromCidr(node.Cidr())
		vpcConfigNodesExternalBlock = append(vpcConfigNodesExternalBlock, thisNodeBlock)
	}
	// 2.
	disjointBlocks := common.DisjointIPBlocks([]*common.IPBlock{cidrsIPBlock}, vpcConfigNodesExternalBlock)
	// 3.
	cidrNodes = make([]Node, 0)
	for _, block := range disjointBlocks {
		if block.ContainedIn(cidrsIPBlock) {
			node, err1 := newExternalNode(true, block)
			if err1 != nil {
				return nil, err1
			}
			cidrNodes = append(cidrNodes, node)
		}
	}
	return cidrNodes, nil
}

// given a string or a vsi or a cidr returns the corresponding node(s)
func (c *VPCConfig) getNodesFromInput(cidrOrName string) ([]Node, error) {
	if vsi := c.getVsiNode(cidrOrName); vsi != nil {
		return []Node{vsi}, nil
	}
	return c.getCidrExternalNodes(cidrOrName)
}

// todo: group results. for now just prints each

// ExplainConnectivity todo: this will not be needed here once we connect explanbility to the cli
// todo: support vsi given as an ID/IP address (CRN?)
// nil conn means connection is not part of the query
func (c *VPCConfig) ExplainConnectivity(src, dst string, connQuery *common.ConnectionSet) (out string, err error) {
	srcNodes, dstNodes, err := c.processInput(src, dst)
	if err != nil {
		return "", err
	}
	potentialRulesAndConnDetails, err1 := c.computeExplainRules(srcNodes, dstNodes, connQuery)
	if err1 != nil {
		return "", err1
	}
	if connQuery == nil { // find the connection between src and dst if connection not specified in query
		err2 := potentialRulesAndConnDetails.computeConnections(c)
		if err2 != nil {
			return "", err2
		}
	}
	actualRulesAndConnDetails := c.computeRouterAndActualRules(&potentialRulesAndConnDetails)
	groupedLines, err3 := newGroupConnExplainability(c, actualRulesAndConnDetails)
	if err3 != nil {
		return "", err3
	}
	res := &explanation{c, connQuery, &potentialRulesAndConnDetails,
		&potentialRulesAndConnDetails, groupedLines.GroupedLines}
	return res.String(), nil
}

// computeExplainRules computes the egress and ingress rules contributing to the (existing or missing) connection <src, dst>
func (c *VPCConfig) computeExplainRules(srcNodes, dstNodes []Node,
	conn *common.ConnectionSet) (rulesAndConn rulesAndConnDetails, err error) {
	rulesAndConn = make(rulesAndConnDetails, max(len(srcNodes), len(dstNodes)))
	i := 0
	// either src of dst has more than one item; never both
	// the loop is on two dimension since we do not know which, but actually we have a single dimension
	for _, src := range srcNodes {
		for _, dst := range dstNodes {
			rulesOfConnection, err := c.getRulesOfConnection(src, dst, conn)
			if err != nil {
				return nil, err
			}
			rulesThisSrcDst := &rulesSingleSrcDst{src, dst, common.NewConnectionSet(false), nil, nil, rulesOfConnection}
			rulesAndConn[i] = rulesThisSrcDst
			i++
		}
	}
	return rulesAndConn, nil
}

// computeActualRules computes from potentialRules the rules that actually enable traffic, considering the filtersExternal
// (which was computed based on the RoutingResource) and (in the near future) considering the combined filters
// at the moment (only SG supported) actual can differ from potential only if src or dst is external
func (c *VPCConfig) computeRouterAndActualRules(potentialRules *rulesAndConnDetails) *rulesAndConnDetails {
	actualRulesAndConn := make(rulesAndConnDetails, len(*potentialRules))
	for i, potential := range *potentialRules {
		src := potential.src
		dst := potential.dst
		// RoutingResources are computed by the parser for []Nodes of the VPC,
		// finds the relevant nodes for the query's src and dst;
		// err indicates no containing node was found, which is an indication there is no router
		containingSrcNode, err1 := c.getContainingConfigNode(src)
		containingDstNode, err2 := c.getContainingConfigNode(dst)
		var routingResource RoutingResource
		if err1 == nil && err2 == nil {
			routingResource, _ = c.getRoutingResource(containingSrcNode, containingDstNode)
		}
		var filtersForExternal map[string]bool
		if routingResource != nil {
			filtersForExternal = routingResource.AppliedFiltersKinds() // relevant filtersExternal
		var routingResource RoutingResource
		var filtersForExternal map[string]bool
		if err1 == nil && err2 == nil {
			routingResource, _ = c.getRoutingResource(containingSrcNode, containingDstNode)
	        	if routingResource != nil {
		        	filtersForExternal = routingResource.AppliedFiltersKinds() // relevant filtersExternal
		        }
		}
		potential.router = routingResource
		potential.filtersExternal = filtersForExternal
		actual := &rulesSingleSrcDst{potential.src, potential.dst, potential.conn, routingResource, filtersForExternal, nil}
		if potential.src.IsInternal() && potential.dst.IsInternal() { // internal: no need for routingResource, copy as is
			actual.rules = potential.rules
		} else { // connection to/from external address; adds only relevant filters
			actualIngress := computeActualRules(&potential.rules.ingressRules, filtersForExternal)
			actualEgress := computeActualRules(&potential.rules.egressRules, filtersForExternal)
			actual.rules = &rulesConnection{*actualIngress, *actualEgress}
		}
		actualRulesAndConn[i] = actual
		actual := *potential
		if !potential.src.IsInternal() || !potential.dst.IsInternal() {
			actualIngress := computeActualRules(&potential.rules.ingressRules, filtersForExternal)
			actualEgress := computeActualRules(&potential.rules.egressRules, filtersForExternal)
			actual.rules = &rulesConnection{*actualIngress, *actualEgress}
		}
	return &actualRulesAndConn
}

func computeActualRules(potentialRules *rulesInLayers, filtersExternal map[string]bool) *rulesInLayers {
	actualRules := rulesInLayers{}
	for filter, potentialRules := range *potentialRules {
		if filtersExternal[filter] {
			actualRules[filter] = potentialRules
		}
	}
	return &actualRules
}

func (c *VPCConfig) processInput(srcName, dstName string) (srcNodes, dstNodes []Node, err error) {
	srcNodes, err = c.getNodesFromInput(srcName)
	if err != nil {
		return nil, nil, err
	}
	if len(srcNodes) == 0 {
		return nil, nil, fmt.Errorf("src %v does not represent a VSI or an external IP", srcName)
	}
	dstNodes, err = c.getNodesFromInput(dstName)
	if err != nil {
		return nil, nil, err
	}
	if len(dstNodes) == 0 {
		return nil, nil, fmt.Errorf("dst %v does not represent a VSI or an external IP", dstName)
	}
	// only one of src/dst can be external; there could be multiple nodes only if external
	if !srcNodes[0].IsInternal() && !dstNodes[0].IsInternal() {
		return nil, nil, fmt.Errorf("both src %v and dst %v are external", srcName, dstName)
	}
	return srcNodes, dstNodes, nil
}

func (c *VPCConfig) getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(
	src, dst Node, conn *common.ConnectionSet, isIngress bool, layer string) (rules *[]RulesInFilter, err error) {
	filter := c.getFilterTrafficResourceOfKind(layer)
	if filter == nil {
		return nil, fmt.Errorf("layer %v not found in configuration", layer)
	}
	rulesOfFilter, err := filter.RulesInConnectivity(src, dst, conn, isIngress)
	if err != nil {
		return nil, err
	}
	return &rulesOfFilter, nil
}

func (c *VPCConfig) getRulesOfConnection(src, dst Node, conn *common.ConnectionSet) (rulesOfConnection *rulesConnection, err error) {
	filterLayers := []string{SecurityGroupLayer}
	rulesOfConnection = &rulesConnection{}
	ingressRulesPerLayer, egressRulesPerLayer := make(rulesInLayers), make(rulesInLayers)
	for _, layer := range filterLayers {
		// ingress rules: relevant only if dst is internal
		if dst.IsInternal() {
			ingressRules, err1 := c.getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(src, dst, conn, true, layer)
			if err1 != nil {
				return nil, err1
			}
			if len(*ingressRules) > 0 {
				ingressRulesPerLayer[layer] = *ingressRules
			}
		}

		// egress rules: relevant only is src is internal
		if src.IsInternal() {
			egressRules, err2 := c.getFiltersEnablingRulesBetweenNodesPerDirectionAndLayer(src, dst, conn, false, layer)
			if err2 != nil {
				return nil, err2
			}
			if len(*egressRules) > 0 {
				egressRulesPerLayer[layer] = *egressRules
			}
		}
	}
	rulesOfConnection.ingressRules = ingressRulesPerLayer
	rulesOfConnection.egressRules = egressRulesPerLayer
	return rulesOfConnection, nil
}

// node is from getCidrExternalNodes, thus there is a node in VPCConfig that either equal to or contains it.
func (c *VPCConfig) getContainingConfigNode(node Node) (Node, error) {
	if node.IsInternal() { // node is not external - nothing to do
		return node, nil
	}
	nodeIPBlock := common.NewIPBlockFromCidr(node.Cidr())
	if nodeIPBlock == nil { // string cidr does not represent a legal cidr
		return nil, fmt.Errorf("could not find IP block of external node %v", node.Name())
	}
	for _, configNode := range c.Nodes {
		if configNode.IsInternal() {
			continue
		}
		configNodeIPBlock := common.NewIPBlockFromCidr(configNode.Cidr())
		if nodeIPBlock.ContainedIn(configNodeIPBlock) {
			return configNode, nil
		}
	}
	return nil, fmt.Errorf("could not find containing config node for %v", node.Name())
}

// prints each separately without grouping - for debug
func (explanationStruct *rulesAndConnDetails) String(c *VPCConfig, connQuery *common.ConnectionSet) (string, error) {
	resStr := ""
	for _, rulesSrcDst := range *explanationStruct {
		resStr += stringExplainabilityLine(c, connQuery, rulesSrcDst.src, rulesSrcDst.dst,
			rulesSrcDst.conn, rulesSrcDst.router, rulesSrcDst.rules)
	}
	return resStr, nil
}

func (explanation *explanation) String() string {
	linesStr := make([]string, len(explanation.groupedLines))
	groupedLines := explanation.groupedLines
	for i, line := range groupedLines {
		linesStr[i] = stringExplainabilityLine(explanation.c, explanation.connQuery, line.src, line.dst, line.commonProperties.conn,
			line.commonProperties.router, line.commonProperties.rules)
	}
	sort.Strings(linesStr)
	return strings.Join(linesStr, "\n") + "\n"
}

func stringExplainabilityLine(c *VPCConfig, connQuery *common.ConnectionSet, src, dst EndpointElem,
	conn *common.ConnectionSet, router RoutingResource, rules *rulesConnection) string {
	needEgress := !src.IsExternal()
	needIngress := !dst.IsExternal()
	noIngressRules := len(rules.ingressRules) == 0 && needIngress
	noEgressRules := len(rules.egressRules) == 0 && needEgress
	egressRulesStr := fmt.Sprintf("Egress Rules:\n~~~~~~~~~~~~~\n%v", rules.egressRules.string(c))
	ingressRulesStr := fmt.Sprintf("Ingress Rules:\n~~~~~~~~~~~~~~\n%v", rules.ingressRules.string(c))
	noConnection := ""
	if connQuery == nil {
		noConnection = fmt.Sprintf("No connection between %v and %v;", src.Name(), dst.Name())
	} else {
		noConnection = fmt.Sprintf("There is no connection \"%v\" between %v and %v;", connQuery.String(), src.Name(), dst.Name())
	}
	resStr := ""
	switch {
	case router == nil && src.IsExternal():
		resStr += fmt.Sprintf("%v no fip router and src is external\n", noConnection)
	case router == nil && dst.IsExternal():
		resStr += fmt.Sprintf("%v no router (fip/pgw) and dst is external\n", noConnection)
	case noIngressRules && noEgressRules:
		resStr += fmt.Sprintf("%v connection blocked both by ingress and egress\n", noConnection)
	case noIngressRules:
		resStr += fmt.Sprintf("%v connection blocked by ingress\n", noConnection)
		if needEgress {
			resStr += egressRulesStr
		}
	case noEgressRules:
		resStr += fmt.Sprintf("%v connection blocked by egress\n", noConnection)
		if needIngress {
			resStr += ingressRulesStr
		}
	default: // there is a connection
		return stringExplainabilityConnection(connQuery, src, dst, conn, router, needEgress, needIngress, egressRulesStr, ingressRulesStr)
	}
	return resStr
}

func stringExplainabilityConnection(connQuery *common.ConnectionSet, src, dst EndpointElem,
	conn *common.ConnectionSet, router RoutingResource,
	needEgress, needIngress bool, egressRulesStr, ingressRulesStr string) string {
	resStr := ""
	if connQuery == nil {
		resStr = fmt.Sprintf("The following connection exists between %v and %v: %v; its enabled by\n", src.Name(), dst.Name(),
			conn.String())
	} else {
		resStr = fmt.Sprintf("Connection %v exists between %v and %v; its enabled by\n", connQuery.String(),
			src.Name(), dst.Name())
	}
	if src.IsExternal() || dst.IsExternal() {
		resStr += "External Router " + router.Kind() + ": " + router.Name() + "\n"
	}
	if needEgress {
		resStr += egressRulesStr
	}
	if needIngress {
		resStr += ingressRulesStr
	}
	return resStr
}

// todo: connectivity is computed for the entire network, even though we need only for specific src, dst pairs
// this is seems the time spent here should be neglectable, not worth the effort of adding dedicated code.
func (explanationStruct *rulesAndConnDetails) computeConnections(c *VPCConfig) error {
	connectivity, err := c.GetVPCNetworkConnectivity(false) // computes connectivity
	if err != nil {
		return err
	}
	for _, rulesSrcDst := range *explanationStruct {
		// is there a connection?
		if (len(rulesSrcDst.rules.egressRules) > 0 || !rulesSrcDst.src.IsInternal()) && // egress enabled or not needed
			(len(rulesSrcDst.rules.ingressRules) > 0 || !rulesSrcDst.dst.IsInternal()) { // ingress enabled or not needed
			conn, err := connectivity.getConnection(c, rulesSrcDst.src, rulesSrcDst.dst)
			if err != nil {
				return err
			}
			rulesSrcDst.conn = conn
		}
	}
	return nil
}

// given that there is a connection between src to dst, gets it
// if src or dst is a node then the node is from getCidrExternalNodes,
// thus there is a node in VPCConfig that either equal to or contains it.
func (v *VPCConnectivity) getConnection(c *VPCConfig, src, dst Node) (conn *common.ConnectionSet, err error) {
	srcForConnection, err1 := c.getContainingConfigNode(src)
	if err1 != nil {
		return nil, err1
	}
	dstForConnection, err2 := c.getContainingConfigNode(dst)
	if err2 != nil {
		return nil, err2
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

func (rulesInLayers *rulesInLayers) string(c *VPCConfig) string {
	rulesInLayersStr := ""
	for layer, rules := range *rulesInLayers {
		filter := c.getFilterTrafficResourceOfKind(layer)
		if filter == nil {
			continue
		}
		rulesInLayersStr += layer + " Rules\n------------------------\n" +
			filter.StringRulesOfFilter(rules)
	}
	return rulesInLayersStr
}
