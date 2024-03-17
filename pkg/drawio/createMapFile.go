package drawio

import (
	_ "embed"
	"fmt"
	"os"
	"reflect"
	"sort"
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
	relations   string
	IsHtml      bool
}

func NewTemplateData(network SquareTreeNodeInterface) *templateData {
	allNodes := getAllNodes(network)
	orderedNodes := orderNodesForTemplate(allNodes)
	data := &templateData{
		newTemplateStyles(allNodes),
		network.Width(),
		network.Height(),
		network.ID(),
		orderedNodes,
		network.DebugPoints(),
		"",
		true,
	}
	data.setRelations(network)
	return data
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
func (data *templateData) Add(a, b int) int     { return a + b }
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
// (if a sg or  a gs is above a square, it will block the the tooltip of the children of the square.)
func orderNodesForTemplate(nodes []TreeNodeInterface) []TreeNodeInterface {
	squareOrders := []SquareTreeNodeInterface{
		&NetworkTreeNode{},
		&PublicNetworkTreeNode{},
		&CloudTreeNode{},
		&VpcTreeNode{},
		&GroupSubnetsSquareTreeNode{},
		&ZoneTreeNode{},
		&SubnetTreeNode{},
		&SGTreeNode{},
		&PartialSGTreeNode{},
		&GroupSquareTreeNode{},
	}
	var ln, ic, orderedNodes []TreeNodeInterface
	squaresBuckets := map[reflect.Type][]TreeNodeInterface{}
	for _, t := range squareOrders {
		squaresBuckets[reflect.TypeOf(t).Elem()] = []TreeNodeInterface{}
	}
	for _, tn := range nodes {
		switch {
		case tn.IsSquare():
			e := reflect.TypeOf(tn).Elem()
			squaresBuckets[e] = append(squaresBuckets[e], tn)
		case tn.IsIcon():
			ic = append(ic, tn)
		case tn.IsLine():
			ln = append(ln, tn)
		}
	}
	for _, gSlice := range [][]TreeNodeInterface{
		squaresBuckets[reflect.TypeOf(&GroupSquareTreeNode{}).Elem()],
		squaresBuckets[reflect.TypeOf(&GroupSubnetsSquareTreeNode{}).Elem()],
	} {
		sort.Slice(gSlice, func(i, j int) bool {
			return gSlice[i].Width() > gSlice[j].Width()
		})
	}
	for _, t := range squareOrders {
		orderedNodes = append(orderedNodes, squaresBuckets[reflect.TypeOf(t).Elem()]...)
	}
	orderedNodes = append(orderedNodes, ic...)
	orderedNodes = append(orderedNodes, ln...)
	return orderedNodes
}

// todo - when implementing the full html solution, need to change this interface:
func CreateDrawioConnectivityMapFile(network SquareTreeNodeInterface, outputFile string, subnetMode bool) error {
	newLayout(network, subnetMode).layout()
	data := NewTemplateData(network)
	if true {
		err := createFileFromTemplate(data, outputFile+".html", svgTemplate)
		if err != nil {
			return err
		}
		data.IsHtml = false
		err = createFileFromTemplate(data, outputFile+".svg", svgTemplate)
		if err != nil {
			return err
		}
	}
	return createFileFromTemplate(data, outputFile, drawioTemplate)
}

func createFileFromTemplate(data *templateData, outputFile, templ string) error {
	tmpl, err := template.New("diagram").Parse(templ)
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
