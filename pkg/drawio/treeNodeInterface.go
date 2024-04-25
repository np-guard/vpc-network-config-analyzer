/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package drawio

import (
	"slices"
	"strings"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

/////////////////////////////////////////////////////////////
// the drawio has three kinds of elements:
// 1. squares (vpcs, zones, sgs, subnets...)
// 2. icons (NIs, VSIs, users ...)
// 3. lines (connectivity, NI===VSI )
//
// The connectivity map is a tree of these elements:
// the root is the network, it has vpcs, icons and connectors as children
// vpc has zones, sg and icons as children
// zones has subnets and icons as children
// sg has icons as children
// subnets has icons as children
// (an exception: one icon can be hold by a sg and a subnet)
//
// The tree is implemented using nodes pointing to each other
// Each element in this tree is a TreeNode.
//
// TreeNode implementation overview:
// TreeNodeInterface is the basic interface, implemented by all TreeNodes.
// SquareTreeNodeInterface contains TreeNodeInterface, implemented by all square TreeNodes (vpcs, zones, sgs, subnets...).
// IconTreeNodeInterface contains TreeNodeInterface, implemented by all icons TreeNodes (NIs, VSIs, users ...).
// LineTreeNodeInterface contains TreeNodeInterface, implemented by all line TreeNodes. (connectivity, NI===VSI )
//
// abstractTreeNode is the basic struct implementing a TreeNode.
// the structs abstractSquareTreeNode, abstractIconTreeNode, abstractLineTreeNode contain abstractTreeNode
// All structs representing a Square (VpcTreeNode, ZoneTreeNode, SubnetTreeNode...) contain abstractSQuareTreeNode
// All structs representing an icons (NITreeNode, GatewayTreeNode, UserTreeNode...) contain abstractIconTreeNode
// All structs representing a line (LogicalLineTreeNode, ConnectivityTreeNode) contain abstractLineTreeNode

// TreeNode main information that a TreeNode holds is:
// 1. information about the tree (its parents, its children)
// 2. information to be used in the drawio template

type TreeNodeInterface interface {
	ID() uint
	TextID() uint
	RouterID() uint
	X() int
	Y() int
	Height() int
	Width() int
	setXY(x, y int)
	setWH(w, h int)
	labels() []string
	Kind() string
	SetKind(string)

	DrawioParent() TreeNodeInterface
	Parent() TreeNodeInterface
	Location() *Location

	setParent(TreeNodeInterface)
	setLocation(location *Location)
	NotShownInDrawio() bool
	SetNotShownInDrawio()
	setID()

	/////////////////////////////
	IsLine() bool
	IsIcon() bool
	IsSquare() bool

	children() ([]SquareTreeNodeInterface, []IconTreeNodeInterface, []LineTreeNodeInterface)
}

// //////////////////////////////////////////////
func setGeometry(tn TreeNodeInterface) {
	if tn.IsIcon() {
		calculateIconGeometry(tn.(IconTreeNodeInterface))
	} else if tn.IsSquare() {
		calculateSquareGeometry(tn.(SquareTreeNodeInterface))
	}
}

// /////////////////////////////////////////////////////////////////////
// getAllNodes() - return all the nodes in the sub tree
type nodesFilter int

const (
	allNodes = iota
	allSquares
	allIcons
	allLines
)

func upcast[T TreeNodeInterface](p []T) []TreeNodeInterface {
	ret := make([]TreeNodeInterface, len(p))
	for i, q := range p {
		ret[i] = TreeNodeInterface(q)
	}
	return ret
}
func downcast[T TreeNodeInterface](p []TreeNodeInterface) []T {
	ret := make([]T, len(p))
	for i, q := range p {
		ret[i] = q.(T)
	}
	return ret
}

func getFilteredNodes(tn TreeNodeInterface, filter nodesFilter) []TreeNodeInterface {
	squares, icons, lines := tn.children()

	children := append(upcast(squares), upcast(icons)...)
	children = append(children, upcast(lines)...)
	var res []TreeNodeInterface
	switch filter {
	case allNodes:
		res = slices.Clone(children)
	case allSquares:
		res = upcast(squares)
	case allIcons:
		res = upcast(icons)
	case allLines:
		res = upcast(lines)
	}
	for _, child := range children {
		sub := getFilteredNodes(child, filter)
		res = append(res, sub...)

	}
	if filter == allNodes ||
		filter == allSquares && tn.IsSquare() ||
		filter == allIcons && tn.IsIcon() ||
		filter == allLines && tn.IsLine() {
		res = append(res, tn)
	}
	res = common.FromList(res).AsList()
	return res
}

func getAllNodes(tn TreeNodeInterface) []TreeNodeInterface {
	return getFilteredNodes(tn, allNodes)
}
func getAllSquares(tn TreeNodeInterface) []TreeNodeInterface {
	return getFilteredNodes(tn, allSquares)
}
func getAllIcons(tn TreeNodeInterface) []TreeNodeInterface {
	return getFilteredNodes(tn, allIcons)
}
func getAllLines(tn TreeNodeInterface) []TreeNodeInterface {
	return getFilteredNodes(tn, allLines)
}
func getAllSquaresTN(tn TreeNodeInterface) (ret []SquareTreeNodeInterface) {
	return downcast[SquareTreeNodeInterface](getAllSquares(tn))
}
func getAllLinesTN(tn TreeNodeInterface) (ret []LineTreeNodeInterface) {
	return downcast[LineTreeNodeInterface](getAllLines(tn))
}
func getAllIconsTN(tn TreeNodeInterface) (ret []IconTreeNodeInterface) {
	return downcast[IconTreeNodeInterface](getAllIcons(tn))
}

func locations(tns []TreeNodeInterface) []*Location {
	locations := []*Location{}
	for _, c := range tns {
		locations = append(locations, c.Location())
	}
	return locations
}

func absoluteGeometry(tn TreeNodeInterface) (x, y int) {
	if tn.DrawioParent() == nil {
		return tn.X(), tn.Y()
	}
	return tn.X() + tn.DrawioParent().Location().firstCol.x() + tn.DrawioParent().Location().xOffset,
		tn.Y() + tn.DrawioParent().Location().firstRow.y() + tn.DrawioParent().Location().yOffset
}

func joinLabels(labels []string, sep string) string {
	labelsToJoin := slices.Clone(labels)
	labelsToJoin = slices.DeleteFunc(labelsToJoin, func(s string) bool { return s == "" })
	return strings.Join(labelsToJoin, sep)
}

func treeNodeName(tn TreeNodeInterface) string {
	return joinLabels(tn.labels(), ",")
}

// uncomment writeAsJson() treeNodeAsMap() for debug of a treeNode

// func treeNodeAsMap(tn TreeNodeInterface) map[string]interface{} {
// 	res := map[string]interface{}{}
// 	squares, icons, lines := tn.children()
// 	sqs := []interface{}{}
// 	ics := []interface{}{}
// 	lns := []interface{}{}
// 	for _, s := range squares {
// 		sqs = append(sqs, treeNodeAsMap(s))
// 	}
// 	for _, s := range icons {
// 		ics = append(ics, treeNodeAsMap(s))
// 	}
// 	for _, s := range lines {
// 		lns = append(lns, treeNodeAsMap(s))
// 	}
// 	res["name"] = tn.labels()
// 	res["squares"] = sqs
// 	res["icons"] = ics
// 	res["lines"] = lns
// 	return res
// }

// func writeTreeNodeToJsonFile(tn TreeNodeInterface, outFile string) {
// 	res, _ := json.MarshalIndent(treeNodeAsMap(tn), "", "    ")
// 	os.WriteFile(outFile, []byte(res), 0o600)
// }
