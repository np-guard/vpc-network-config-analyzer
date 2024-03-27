package drawio

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

func nodeParents(node TreeNodeInterface) []TreeNodeInterface {
	if node == nil {
		return nil
	}
	return append(nodeParents(node.Parent()), node)
}
func nodeSubTree(node TreeNodeInterface) []TreeNodeInterface {
	nodes := getAllSquares(node)
	for _,icon := range getAllIcons(node){
		if !icon.(IconTreeNodeInterface).IsGroupingPoint(){
			nodes = append(nodes, icon)
		}
	}
	return nodes
}

type lineInfo struct {
	mainLine                           LineTreeNodeInterface
	src, dst                           TreeNodeInterface
	router                             TreeNodeInterface
	srcGroupingLines, dstGroupingLines []LineTreeNodeInterface
	srcGroupingPoint, dstGroupingPoint TreeNodeInterface
}

func getLineInfo(line LineTreeNodeInterface) *lineInfo {
	src := line.Src()
	dst := line.Dst()
	info := &lineInfo{line, src, dst, line.Router(), nil, nil, nil, nil}

	srcIsGP := src.IsIcon() && src.(IconTreeNodeInterface).IsGroupingPoint()
	dstIsGP := dst.IsIcon() && dst.(IconTreeNodeInterface).IsGroupingPoint()

	if srcIsGP && slices.Contains(src.(*GroupPointTreeNode).groupedIconsConns, line) ||
		dstIsGP && slices.Contains(dst.(*GroupPointTreeNode).groupedIconsConns, line) {
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
	return info
}

func lineRelation(info *lineInfo) []TreeNodeInterface {
	res := []TreeNodeInterface{info.mainLine}
	for _, node := range []TreeNodeInterface{info.src, info.dst} {
		res = append(res, nodeParents(node)...)
		res = append(res, nodeSubTree(node)...)
	}
	for _, node := range []TreeNodeInterface{info.router, info.srcGroupingPoint, info.dstGroupingPoint} {
		if node != nil {
			res = append(res, node)
		}
	}
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
func sgRelation(sgTn *SGTreeNode) (psg, icons []TreeNodeInterface) {
	for _, psgTn := range sgTn.partialSgs {
		psg = append(psg, psgTn)
	}
	for _, icon := range sgTn.elements {
		icons = append(icons, icon)
	}
	return psg, icons
}

func tnRelations(network TreeNodeInterface) map[TreeNodeInterface][]TreeNodeInterface {
	res := map[TreeNodeInterface][]TreeNodeInterface{}
	// all parents of the nodes
	for _, node := range getAllNodes(network) {
		res[node] = nodeParents(node)
	}

	for _, line := range getAllLines(network) {
		info := getLineInfo(line)
		if info == nil {
			continue
		}
		lineRelations := lineRelation(info)
		for _, relatedTn := range lineRelations {
			res[relatedTn] = append(res[relatedTn], lineRelations...)
		}
	}

	for _, node := range getAllSquares(network) {
		res[node] = append(res[node], nodeSubTree(node)...)
		if sgTn, ok := node.(*SGTreeNode); ok {
			sgSquares, sgIcons := sgRelation(sgTn)
			for _, i := range sgIcons {
				res[i] = append(res[i], sgSquares...)
			}
			for _, s := range sgSquares {
				for _, i := range sgIcons {
					res[s] = append(res[s], res[i]...)
				}
			}

		}
	}
	for n, r := range res {
		res[n] = common.FromList[TreeNodeInterface](r).AsList()
	}
	return res
}
func (data *templateData)setNodesNames(network TreeNodeInterface) {
	// all parents of the nodes
	for _, tn := range getAllNodes(network) {
		data.svgNames[tn] = fmt.Sprintf("%s:%s",tn.Kind(), treeNodeName(tn))
	}

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

/////////////////////////////////////////////////////////////////////////////

func (data *templateData) setNodesRelations(network TreeNodeInterface) {
	rel := tnRelations(network)
	res := map[string]map[string][]string{}
	for _, node := range data.Nodes {
		nId := strconv.Itoa(int(node.ID()))
		res[nId] = map[string][]string{}
		res[nId]["relations"] = []string{strconv.Itoa(int(data.RootID()))}
		for _, n := range rel[node] {
			res[nId]["relations"] = append(res[nId]["relations"], strconv.Itoa(int(n.ID())))
		}
		res[nId]["explanation"] = []string{"Connectivity graph of " + data.NodeName(node)}
	}
	b, _ := json.Marshal(res)
	data.Relations = string(b)
}

