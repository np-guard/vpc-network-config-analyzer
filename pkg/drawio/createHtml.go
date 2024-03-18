package drawio

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	"github.com/np-guard/vpc-network-config-analyzer/pkg/common"
)

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

func nodeParents(node TreeNodeInterface) []TreeNodeInterface {
	if node == nil {
		return nil
	}
	return append(nodeParents(node.Parent()), node)
}

func lineRelation(info *lineInfo) []TreeNodeInterface {
	res := []TreeNodeInterface{info.mainLine}
	res = append(res, nodeParents(info.src)...)
	res = append(res, nodeParents(info.dst)...)
	if info.router != nil {
		res = append(res, info.router)
	}
	for _, node := range []TreeNodeInterface{info.src, info.dst} {
		res = append(res, getAllIcons(node)...)
		res = append(res, getAllSquares(node)...)
	}
	if info.srcGroupingPoint != nil {
		res = append(res, info.srcGroupingPoint)
	}
	if info.dstGroupingPoint != nil {
		res = append(res, info.dstGroupingPoint)
	}
	for _, l := range info.srcGroupingLines {
		res = append(res, l)
		res = append(res, getAllIcons(l.Src())...)
		res = append(res, getAllSquares(l.Src())...)
	}
	for _, l := range info.dstGroupingLines {
		res = append(res, l)
		res = append(res, getAllIcons(l.Dst())...)
		res = append(res, getAllSquares(l.Dst())...)
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
	router := line.Router()

	srcIsGP := src.IsIcon() && src.(IconTreeNodeInterface).IsGroupingPoint()
	dstIsGP := dst.IsIcon() && dst.(IconTreeNodeInterface).IsGroupingPoint()
	switch {
	case !srcIsGP && !dstIsGP:
		return &lineInfo{line, src, dst, router, nil, nil, nil, nil}
	case srcIsGP && dstIsGP:
		return &lineInfo{line, src.Parent(), dst.Parent(), router,
			src.(*GroupPointTreeNode).groupedIconsConns,
			dst.(*GroupPointTreeNode).groupedIconsConns,
			src, dst}
	case srcIsGP && !slices.Contains(src.(*GroupPointTreeNode).groupedIconsConns, line):
		return &lineInfo{line, src.Parent(), dst, router,
			src.(*GroupPointTreeNode).groupedIconsConns,
			nil,
			src, nil}
	case dstIsGP && !slices.Contains(dst.(*GroupPointTreeNode).groupedIconsConns, line):
		return &lineInfo{line, src, dst.Parent(), router,
			nil,
			dst.(*GroupPointTreeNode).groupedIconsConns,
			nil, dst}
	}
	return nil
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
		for _, i := range lineRelations {
			res[i] = append(res[i], lineRelations...)
		}
	}

	for _, node := range getAllSquares(network) {
		res[node] = append(res[node], getAllIcons(node)...)
		res[node] = append(res[node], getAllSquares(node)...)
	}
	for n,r := range res{
		res[n] = common.FromList[TreeNodeInterface](r).AsList()
	}
	return res
}

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
