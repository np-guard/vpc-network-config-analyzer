package drawio

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

func nodeParents(node TreeNodeInterface) []TreeNodeInterface {
	if node == nil {
		return nil
	}
	return append(nodeParents(node.Parent()), node)
}
func nodeSubTree(node TreeNodeInterface) []TreeNodeInterface {
	return append(getAllSquares(node), getAllIcons(node)...)
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
	}
	for n, r := range res {
		res[n] = common.FromList[TreeNodeInterface](r).AsList()
	}
	return res
}

/////////////////////////////////////////////////////////////////////////////

func (data *templateData) nodesRelations(network TreeNodeInterface) map[string]map[string][]string {
	rel := tnRelations(network)
	res := map[string]map[string][]string{}
	res[""] = map[string][]string{}
	res[""]["relations"] = []string{data.SvgRootId()}
	res[""]["highlights"] = []string{""}
	res[""]["explanation"] = []string{"expl of All"}
	for _, node := range data.Nodes {
		nId := data.SvgId(node)
		res[nId] = map[string][]string{}
		res[nId]["relations"] = []string{data.SvgRootId()}
		for _, n := range rel[node] {
			res[nId]["relations"] = append(res[nId]["relations"], data.SvgId(n))
		}
		res[""]["relations"] = append(res[""]["relations"], nId)
		res[nId]["highlights"] = []string{nId}
		res[nId]["explanation"] = []string{"expl of " + data.SvgName(node)}

	}
	return res
}

func (data *templateData) SvgId(tn TreeNodeInterface) string {
	name := reflect.TypeOf(tn).Elem().Name()[0:5]
	return fmt.Sprintf("%s_%d", name, tn.ID())
}
func (data *templateData) SvgName(tn TreeNodeInterface) string {
	return "the name of " + data.SvgId(tn)
}
func (data *templateData) SvgRootId() string {
	return fmt.Sprintf("%s_%d", "top", data.rootID)
}

///////////////////////////////////////////////

func (data *templateData) setRelations(network TreeNodeInterface) {
	b, _ := json.Marshal(data.nodesRelations(network))
	data.relations = string(b)
}
func (data *templateData) Relations() string {
	return data.relations
}
func (data *templateData) Entries() string {
	return ""
}
