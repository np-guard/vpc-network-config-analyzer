package drawio

import (
	_ "embed"
	"fmt"
	"os"
	"reflect"
	"text/template"
)

//go:embed connectivityMap.drawio.tmpl
var drawioTemplate string

//go:embed connectivityMap.svg.tmpl
var svgTemplate string

type templateData struct {
	templateStyles
	Width       int
	Height      int
	rootID      uint
	Nodes       []TreeNodeInterface
	DebugPoints []debugPoint
}

func NewTemplateData(network SquareTreeNodeInterface) *templateData {
	allNodes := getAllNodes(network)
	orderedNodes := orderNodesForTemplate(allNodes)
	return &templateData{
		newTemplateStyles(allNodes),
		network.Width(),
		network.Height(),
		network.ID(),
		orderedNodes,
		network.DebugPoints(),
	}
}
func (data *templateData) FipXOffset() int      { return fipXOffset }
func (data *templateData) FipYOffset() int      { return fipYOffset }
func (data *templateData) MiniIconXOffset() int { return miniIconXOffset }
func (data *templateData) MiniIconYOffset() int { return miniIconYOffset }
func (data *templateData) MiniIconSize() int    { return miniIconSize }
func (data *templateData) RootID() uint         { return data.rootID }
func (data *templateData) IDsPrefix() string    { return idsPrefix }
func (data *templateData) ElementComment(tn TreeNodeInterface) string {
	return reflect.TypeOf(tn).Elem().Name() + " " + tn.Label()
}
func (data *templateData) Add(a int, b int) int { return a + b }
func (data *templateData) Add3(a, b, c int) int { return a + b + c }
func (data *templateData) Half(a int) int       { return a / 2 }

func (data *templateData) AX(tn TreeNodeInterface) int {
	x, _ := absoluteGeometry(tn)
	return x
}
func (data *templateData) AY(tn TreeNodeInterface) int {
	_, y := absoluteGeometry(tn)
	return y
}

// orderNodesForTemplate() sort the nodes for the drawio/svg canvas
// the order in the drawio/svg canvas are set by the order in the drawio/svg file
// (the last in the file will be on top in the canvas)
// 1. we put the lines at the top so they will overlap the icons
// 2. we put the icons above the squares so we can mouse over it for tooltips
// 3. we put the sgs and the gs in the bottom.
// (if a sg ot a gs is above a square, it will block the the tooltip of the children of the square.)
func orderNodesForTemplate(nodes []TreeNodeInterface) []TreeNodeInterface {
	var sg, sq, ln, ic, gs, orderedNodes []TreeNodeInterface
	for _, tn := range nodes {
		switch {
		case reflect.TypeOf(tn).Elem() == reflect.TypeOf(PartialSGTreeNode{}):
			sg = append(sg, tn)
		case tn.IsSquare() && tn.(SquareTreeNodeInterface).IsGroupingSquare(),
			tn.IsSquare() && tn.(SquareTreeNodeInterface).IsGroupSubnetsSquare():
			gs = append(gs, tn)
		case tn.IsSquare():
			sq = append(sq, tn)
		case tn.IsIcon():
			ic = append(ic, tn)
		case tn.IsLine():
			ln = append(ln, tn)
		}
	}
	orderedNodes = append(orderedNodes, gs...)
	orderedNodes = append(orderedNodes, sg...)
	orderedNodes = append(orderedNodes, sq...)
	orderedNodes = append(orderedNodes, ic...)
	orderedNodes = append(orderedNodes, ln...)
	return orderedNodes
}

// todo - when implementing the full html solution, need to change this interface:
func CreateDrawioConnectivityMapFile(network SquareTreeNodeInterface, outputFile string, subnetMode bool) error {
	newLayout(network, subnetMode).layout()
	if true {
		createFileFromTemplate(network, outputFile+".svg", "connectivityMap.svg.tmpl", svgTemplate)
	}
	return createFileFromTemplate(network, outputFile, "connectivityMap.drawio.tmpl", drawioTemplate)
}

func createFileFromTemplate(network SquareTreeNodeInterface, outputFile, tmplName, templ string) error {
	data := NewTemplateData(network)
	tmpl, err := template.New(tmplName).Parse(templ)
	if err != nil {
		return err
	}
	fo, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	// close fo on exit and check for its returned error
	defer func() {
		if closeErr := fo.Close(); closeErr != nil {
			fmt.Println("Error when closing:", closeErr)
		}
	}()
	err = tmpl.Execute(fo, data)
	return err
}
