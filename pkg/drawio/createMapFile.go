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

type drawioData struct {
	drawioStyles
	rootID uint
	Nodes  []TreeNodeInterface
}

func NewDrawioData(network SquareTreeNodeInterface) *drawioData {
	allNodes := getAllNodes(network)
	orderedNodes := orderNodesForDrawio(allNodes)
	return &drawioData{
		newDrawioStyles(allNodes),
		network.ID(),
		orderedNodes,
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

	return writeDrawioFile(NewDrawioData(network), outputFile)
}

func writeDrawioFile(data *drawioData, outputFile string) error {
	tmpl, err := template.New("connectivityMap.drawio.tmpl").Parse(drawioTemplate)
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
