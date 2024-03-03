package drawio

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
)

//go:embed connectivityMap.html.tmpl
var htmlTemplate string

//go:embed connectivityMap.svg.body.tmpl
var svgBodyTemplate string

func (data *templateData) SvgId(tn TreeNodeInterface) string {
	name := reflect.TypeOf(tn).Elem().Name()[0:5]
	return fmt.Sprintf("%s_%d", name, tn.ID())
}
func (data *templateData) SvgRootId() string {
	return fmt.Sprintf("%s_%d", "top", data.rootID)
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
		res[nId]["relations"] = []string{nId, data.SvgRootId()}
		res[""]["relations"] = append(res[""]["relations"], nId)
		p := node.Parent()
		if p != nil {
			res[nId]["relations"] = append(res[nId]["relations"], data.SvgId(p))
		}
		res[nId]["highlights"] = []string{nId}
		res[nId]["explanation"] = []string{"expl of " + node.Label()}

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
func (data *templateData) SvgBody() string {
	return svgBody
}

var svgBody string

func createHtml(network SquareTreeNodeInterface, outputFile string) error {

	createFileFromTemplate(network, outputFile+".svgBody", "connectivityMap.svg.body.tmpl", svgBodyTemplate)
	svgBodyBytes, _ := os.ReadFile(outputFile + ".svgBody")
	os.Remove(outputFile + ".svgBody")
	svgBody = string(svgBodyBytes)
	return createFileFromTemplate(network, outputFile+".html", "connectivityMap.html.tmpl", htmlTemplate)

}
