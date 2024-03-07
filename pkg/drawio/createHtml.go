package drawio

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"

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
func lineRelation(multiLine []TreeNodeInterface) (res, srcs, dsts []TreeNodeInterface, router TreeNodeInterface) {
	for _, line := range multiLine {
		src := line.(LineTreeNodeInterface).Src()
		dst := line.(LineTreeNodeInterface).Dst()
		if src.IsIcon() && src.(IconTreeNodeInterface).IsGroupingPoint() {
			src = src.Parent()
		}
		if dst.IsIcon() && dst.(IconTreeNodeInterface).IsGroupingPoint() {
			dst = dst.Parent()
		}
		router = line.(LineTreeNodeInterface).Router()
		res = append(res, line)
		res = append(res, nodeParents(src)...)
		res = append(res, nodeParents(dst)...)
		if router != nil {
			res = append(res, router)
		}
		for _, node := range []TreeNodeInterface{src, dst} {
			if node.IsSquare() {
				res = append(res, getAllIcons(node)...)
				res = append(res, getAllSquares(node)...)
			}
		}
		srcs = append(srcs, src)
		dsts = append(dsts, dst)
		srcs = append(srcs, getAllIcons(src)...)
		dsts = append(dsts, getAllSquares(src)...)
	}
	return res, srcs, dsts, router
}

func nodesRelations(network TreeNodeInterface) map[TreeNodeInterface][]TreeNodeInterface {
	res := map[TreeNodeInterface][]TreeNodeInterface{}
	for _, node := range getAllNodes(network) {
		res[node] = nodeParents(node)
	}
	multiLines := map[TreeNodeInterface]common.GenericSet[TreeNodeInterface]{}
	for _, line := range getAllLines(network) {
		for _, node := range []TreeNodeInterface{line.Src(), line.Dst()} {
			if node.IsIcon() && node.(IconTreeNodeInterface).IsGroupingPoint() {
				multiLines[node] = common.GenericSet[TreeNodeInterface]{}
			}
		}
	}
	for _, line := range getAllLines(network) {
		srcIsGP := line.Src().IsIcon() && line.Src().(IconTreeNodeInterface).IsGroupingPoint()
		dstIsGP := line.Dst().IsIcon() && line.Dst().(IconTreeNodeInterface).IsGroupingPoint()
		if srcIsGP {
			multiLines[line.Src()][line] = true
		}
		if dstIsGP {
			multiLines[line.Dst()][line] = true
		}
		if !srcIsGP && !dstIsGP {
			multiLines[line] = common.GenericSet[TreeNodeInterface]{line: true}
		}
	}
	for _, line := range getAllLines(network) {
		if line.Src().IsIcon() && line.Src().(IconTreeNodeInterface).IsGroupingPoint() &&
			line.Dst().IsIcon() && line.Dst().(IconTreeNodeInterface).IsGroupingPoint() {
				multiLines[line.Src()].Merge(multiLines[line.Dst()])
			delete(multiLines, line.Dst())
		}
	}

	for _, multiLine := range multiLines {
		lineRelations, srcs, dsts, router := lineRelation(multiLine.AsList())
		all := append(multiLine.AsList(), srcs...)
		all = append(all, dsts...)
		if router != nil {
			all = append(all, router)
		}
		for _, i := range all {
			res[i] = append(res[i], lineRelations...)
		}
	}
	for _, node := range getAllSquares(network) {
		res[node] = append(res[node], getAllIcons(node)...)
		res[node] = append(res[node], getAllSquares(node)...)
	}
	return res
}

func (data *templateData) nodesRelations(network TreeNodeInterface) map[string]map[string][]string {
	rel := nodesRelations(network)
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
