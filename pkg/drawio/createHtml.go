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

func nodeBasicRelations(node TreeNodeInterface) []TreeNodeInterface {
	if node == nil {
		return nil
	}
	return append(nodeBasicRelations(node.Parent()), node)
}

func nodeRelations(node TreeNodeInterface) []TreeNodeInterface {
	res := nodeBasicRelations(node)
	if node.IsLine() {
		res = append(res, nodeBasicRelations(node.(LineTreeNodeInterface).Src())...)
		res = append(res, nodeBasicRelations(node.(LineTreeNodeInterface).Dst())...)
	}
	return res
}
func (data *templateData) nodesRelations(nodes []TreeNodeInterface) map[string]map[string][]string {
	res := map[string]map[string][]string{}
	res[""] = map[string][]string{}
	res[""]["relations"] = []string{data.SvgRootId()}
	res[""]["highlights"] = []string{""}
	res[""]["explanation"] = []string{"expl of All"}
	for _, node := range nodes {
		nId := data.SvgId(node)
		res[nId] = map[string][]string{}
		res[nId]["relations"] = []string{data.SvgRootId()}
		for _, n := range nodeRelations(node) {
			res[nId]["relations"] = append(res[nId]["relations"], data.SvgId(n))
		}
		res[""]["relations"] = append(res[""]["relations"], nId)
		res[nId]["highlights"] = []string{nId}
		res[nId]["explanation"] = []string{"expl of " + data.SvgName(node)}

	}
	return res
}
func (data *templateData) Relations() string {
	b, _ := json.Marshal(data.nodesRelations(data.Nodes))
	return string(b)
}
func (data *templateData) Entries() string {
	return ""
}
