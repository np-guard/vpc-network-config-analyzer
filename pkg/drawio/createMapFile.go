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

type drawioData struct {
	drawioStyles
	Width       int
	Height      int
	rootID      uint
	Nodes       []TreeNodeInterface
	DebugPoints []debugPoint
}

func NewDrawioData(network SquareTreeNodeInterface) *drawioData {
	allNodes := getAllNodes(network)
	orderedNodes := orderNodesForDrawio(allNodes)
	return &drawioData{
		newDrawioStyles(allNodes),
		network.Width(),
		network.Height(),
		network.ID(),
		orderedNodes,
		network.DebugPoints(),
	}
}
func (data *drawioData) FipXOffset() int      { return fipXOffset }
func (data *drawioData) FipYOffset() int      { return fipYOffset }
func (data *drawioData) MiniIconXOffset() int { return miniIconXOffset }
func (data *drawioData) MiniIconYOffset() int { return miniIconYOffset }
func (data *drawioData) MiniIconSize() int    { return miniIconSize }
func (data *drawioData) RootID() uint         { return data.rootID }
func (data *drawioData) IDsPrefix() string    { return idsPrefix }
func (data *drawioData) ElementComment(tn TreeNodeInterface) string {
	return reflect.TypeOf(tn).Elem().Name() + " " + tn.Label()
}
func (data *drawioData) Add(a int, b int) int          { return a + b }
func (data *drawioData) Add3(a, b, c int) int          { return a + b + c }
func (data *drawioData) Half(a int) int                { return a / 2 }

func (data *drawioData) AX(tn TreeNodeInterface) int {
	x, _ := absoluteGeometry(tn)
	return x
}
func (data *drawioData) AY(tn TreeNodeInterface) int {
	_, y := absoluteGeometry(tn)
	return y
}

// orderNodesForDrawio() sort the nodes for the drawio canvas
// the order in the drawio canvas are set by the order in the drawio file
// (the last in the file will be on top in the canvas)
// 1. we put the lines at the top so they will overlap the icons
// 2. we put the icons above the squares so we can mouse over it for tooltips
// 3. we put the sgs and the gs in the bottom.
// (if a sg ot a gs is above a square, it will block the the tooltip of the children of the square.)
func orderNodesForDrawio(nodes []TreeNodeInterface) []TreeNodeInterface {
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

func CreateDrawioConnectivityMapFile(network SquareTreeNodeInterface, outputFile string, subnetMode bool) error {
	newLayout(network, subnetMode).layout()
	writeDrawioFile(network, outputFile, "connectivityMap.drawio.tmpl", drawioTemplate)
	return writeDrawioFile(network, outputFile+".svg", "connectivityMap.svg.tmpl", svgTemplate)
}

func writeDrawioFile(network SquareTreeNodeInterface, outputFile, tmplName, templ string) error {
	data := NewDrawioData(network)
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
