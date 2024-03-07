package drawio

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
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
func lineRelation(line TreeNodeInterface) (res []TreeNodeInterface, src, dst, router TreeNodeInterface) {
	src = line.(LineTreeNodeInterface).Src()
	dst = line.(LineTreeNodeInterface).Dst()
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
	return res, src, dst, router
}

func nodesRelations(nodes []TreeNodeInterface) map[TreeNodeInterface][]TreeNodeInterface {
	res := map[TreeNodeInterface][]TreeNodeInterface{}
	for _, node := range nodes {
		res[node] = nodeParents(node)
	}
	for _, node := range nodes {
		switch {
		case node.IsLine():
			lineRelations, src, dst, router := lineRelation(node)
			res[src] = append(res[src], lineRelations...)
			res[dst] = append(res[dst], lineRelations...)
			res[node] = append(res[dst], lineRelations...)
			if router != nil {
				res[router] = append(res[router], lineRelations...)
			}

		case node.IsSquare():
			res[node] = append(res[node], getAllIcons(node)...)
			res[node] = append(res[node], getAllSquares(node)...)
		}
	}
	return res
}

func (data *templateData) nodesRelations(nodes []TreeNodeInterface) map[string]map[string][]string {
	rel := nodesRelations(nodes)
	res := map[string]map[string][]string{}
	res[""] = map[string][]string{}
	res[""]["relations"] = []string{data.SvgRootId()}
	res[""]["highlights"] = []string{""}
	res[""]["explanation"] = []string{"expl of All"}
	for _, node := range nodes {
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
func (data *templateData) setRelations() {
	b, _ := json.Marshal(data.nodesRelations(data.Nodes))
	data.relations = string(b)
}
func (data *templateData) Relations() string {
	return data.relations
}
func (data *templateData) Entries() string {
	return ""
}
