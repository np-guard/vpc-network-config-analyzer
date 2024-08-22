/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package drawio

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

//////////////////////////////////////////////////////////////////////
// setNodesRelations() set for each node N, what are the related nodes to be displayed when the html is filtered by N
/////////////////////////////////////////////////////////////////////////////

func (data *templateData) setNodesRelations(network TreeNodeInterface) {
	rel := tnRelations(network)
	res := map[string]map[string][]string{}
	for _, node := range data.Nodes {
		nodeID := common.UintToString(node.ID())
		res[nodeID] = map[string][]string{}
		nodeRelations := []string{common.UintToString((data.RootID()))}
		for _, n := range rel[node] {
			nodeRelations = append(nodeRelations, common.UintToString(n.ID()))
		}
		res[nodeID]["relations"] = nodeRelations
		res[nodeID]["graphExplanation"] = []string{"Connectivity graph of " + data.NodeName(node)}
	}
	b, _ := json.Marshal(res)
	data.Relations = string(b)
}

// setNodesNames() set the name of each node
func (data *templateData) setNodesNames(network TreeNodeInterface) {
	// all parents of the nodes
	for _, tn := range getAllNodes(network) {
		data.svgNames[tn] = fmt.Sprintf("%s:%s", tn.Kind(), treeNodeName(tn))
	}
	// for a grouped line, all its lines and grouping icons get the same name:
	for _, line := range getAllLines(network) {
		info := getLineInfo(line)
		if info == nil {
			continue
		}
		for _, tn := range append(info.dstGroupingLines, info.srcGroupingLines...) {
			data.svgNames[tn] = data.svgNames[line]
		}
		data.svgNames[info.srcGroupingPoint] = data.svgNames[line]
		data.svgNames[info.dstGroupingPoint] = data.svgNames[line]
	}
}

// nodeParents() - return the parents - basically, if node is presented, all its parents are presented
func nodeParents(node TreeNodeInterface) []TreeNodeInterface {
	if node == nil {
		return nil
	}
	return append(nodeParents(node.Parent()), node)
}

// nodeSubTree() - return the subtree - basically, all the subtree of a square is presented with the square
func nodeSubTree(node TreeNodeInterface) []TreeNodeInterface {
	nodes := getAllSquaresAsTNs(node)
	for _, icon := range getAllIcons(node) {
		if !icon.IsGroupingPoint() {
			nodes = append(nodes, icon)
		}
	}
	return nodes
}

// sgTreeNodes() calc the SG tn that are part of the SG (spatial case of getSubtree() )
// SG can have in more than one  case
func sgTreeNodes(sgTn *SGTreeNode) (psg, icons []TreeNodeInterface) {
	for _, psgTn := range sgTn.partialSgs {
		psg = append(psg, psgTn)
	}
	for _, icon := range sgTn.elements {
		icons = append(icons, icon)
	}
	return psg, icons
}

// lineInfo is a struct with all the treeNodes representing a grouping line:
// for example, for a connection  A,B -> C,D we will have the following on the canvas:
// A->gp1, B->gp1, gp1->gp2, gp2->C, gp2->D
// we have a groupSquares for [A,B] and [C,D], these are hold as src and dst.
// (notice that A,B,C,D are not stored here)
type lineInfo struct {
	mainLine                           LineTreeNodeInterface
	src, dst                           TreeNodeInterface
	router                             TreeNodeInterface
	srcGroupingLines, dstGroupingLines []LineTreeNodeInterface
	srcGroupingPoint, dstGroupingPoint TreeNodeInterface
}

// getLineInfo() calc all the treeNodes representing a grouping line (or just a line) and return it in a lineInfo struct
func getLineInfo(line LineTreeNodeInterface) *lineInfo {
	src := line.Src()
	dst := line.Dst()
	info := &lineInfo{line, src, dst, line.Router(), nil, nil, nil, nil}

	srcIsGP := src.IsIcon() && src.(IconTreeNodeInterface).IsGroupingPoint()
	dstIsGP := dst.IsIcon() && dst.(IconTreeNodeInterface).IsGroupingPoint()

	if srcIsGP && slices.Contains(src.(*GroupPointTreeNode).groupedIconsConns, line) ||
		dstIsGP && slices.Contains(dst.(*GroupPointTreeNode).groupedIconsConns, line) {
		// this is the case that the line is one of the A->gp1, B->gp1, gp2->C, gp2->D
		return nil
	}
	if srcIsGP {
		info.src = src.Parent()
		info.srcGroupingLines = src.(*GroupPointTreeNode).groupedIconsConns
		info.srcGroupingPoint = src
	}
	if dstIsGP {
		info.dst = dst.Parent()
		info.dstGroupingLines = dst.(*GroupPointTreeNode).groupedIconsConns
		info.dstGroupingPoint = dst
	}
	// if both src and dst are not grouping point, its just a regular line, wo any grouping.
	// in this case, the info struct contains only: line, src, dst, and router.
	return info
}

// lineRelation() calc for each line the related treeNodes related to the line
func lineRelation(info *lineInfo) []TreeNodeInterface {
	res := []TreeNodeInterface{info.mainLine}
	// parents of src and dst
	for _, node := range []TreeNodeInterface{info.src, info.dst} {
		res = append(res, nodeParents(node)...)
		res = append(res, nodeSubTree(node)...)
	}
	for _, node := range []TreeNodeInterface{info.router, info.srcGroupingPoint, info.dstGroupingPoint} {
		if node != nil {
			res = append(res, node)
		}
	}
	// adding the grouping lines, and the icons/squares connected to them (the A,B,C,D):
	for _, l := range info.srcGroupingLines {
		res = append(res, l)
		res = append(res, nodeSubTree(l.Src())...)
	}
	for _, l := range info.dstGroupingLines {
		res = append(res, l)
		res = append(res, nodeSubTree(l.Dst())...)
	}
	return res
}

// tnRelations() calc all the relations of all nodes
func tnRelations(network TreeNodeInterface) map[TreeNodeInterface][]TreeNodeInterface {
	res := map[TreeNodeInterface][]TreeNodeInterface{}
	// all parents of the nodes are added:
	for _, node := range getAllNodes(network) {
		res[node] = nodeParents(node)
	}
	// handle lines:
	for _, line := range getAllLines(network) {
		info := getLineInfo(line)
		if info == nil {
			continue
		}
		// each node related to a line get all the other nodes:
		lineRelations := lineRelation(info)
		for _, relatedTn := range lineRelations {
			res[relatedTn] = append(res[relatedTn], lineRelations...)
		}
	}

	for _, node := range getAllSquares(network) {
		// all squares gets the subtree
		res[node] = append(res[node], nodeSubTree(node)...)
		if sgTn, ok := node.(*SGTreeNode); ok {
			sgSquares, sgIcons := sgTreeNodes(sgTn)
			// all sg icons get all the sg squares:
			for _, i := range sgIcons {
				res[i] = append(res[i], sgSquares...)
			}
			// all sg squares get all the sg icons:
			for _, s := range sgSquares {
				for _, i := range sgIcons {
					res[s] = append(res[s], res[i]...)
				}
			}
		}
	}
	// remove duplicates:
	for n, r := range res {
		res[n] = common.FromList[TreeNodeInterface](r).AsList()
	}
	return res
}
