package vpcmodel

// stage 1: vsi to vsi of the same subnet for which a connection exist
//          this is relatively simple since only SG can effect this connection, and SG has only enabling rules

// stage 1:
// input: src and dst, both vsi names in string
// 1. Translate src and dst to Nodes
// 2. Find the ingress and egress rules enabling the connection in the SGAnalyzer struct.
//    specifically, the []*SGRule ingressRules and egressRules contributing to the connection.
//    There are two alternatives of achieving this:
//    * adding the following functionality:
//      func (sg *SecurityGroup) ConnOfSGRules(src, dst vpcmodel.Node, isIngress bool) []*SGRule/[]uniqueIdsOfSGRules
//      whose functionality is similar to that of
//              func (sg *SecurityGroup) AllowedConnectivity(src, dst vpcmodel.Node, isIngress bool) *common.ConnectionSet
//      and for the most part based on the same code
//    * Enhancing the structure
//        type ConnectivityResult struct {
//       by adding to it the list of the rules contributing to the connection []*SGRule/[]uniqueIdsOfSGRules
//  3. Extract the actual sg rules from *SGRule and print as output.
//
//     * pointer to the original rule has to be added to SGRule struct [perhaps the first PR here]
