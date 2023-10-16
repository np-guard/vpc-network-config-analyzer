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
	FipXOffset int
	FipYOffset int
	MiniIconXOffset int
	MiniIconYOffset int
	MiniIconSize    int
	RootID     uint
	IDsPrefix  string
	// ShowNIIcon says if to display the NI as an NI image, or a VSI image
	// the rule is that if we have a vsi icon, then we display the NI icon as an NI image
	ShowNIIcon bool
	ShowResIPIcon bool
	Nodes      []TreeNodeInterface
}

// orderNodesForDrawio() sort the nodes for the drawio canvas
// the order in the drawio canvas are set by the order in the drawio file
// (the last in the file will be on top in the canvas)
// 1. we put the lines at the top so they will overlap the icons
// 2. we put the icons above the squares so we can mouse over it for tooltips
// 3. we put the sgs in the bottom. if a sg is above a square, it will block the the tooltip of the children of the square.
func orderNodesForDrawio(nodes []TreeNodeInterface) []TreeNodeInterface {
	var sg, sq, ln, ic, orderedNodes []TreeNodeInterface
	for _, tn := range nodes {
		switch {
		case reflect.TypeOf(tn).Elem() == reflect.TypeOf(PartialSGTreeNode{}):
			sg = append(sg, tn)
		case tn.IsSquare():
			sq = append(sq, tn)
		case tn.IsIcon():
			ic = append(ic, tn)
		case tn.IsLine():
			ln = append(ln, tn)
		}
	}
	orderedNodes = append(orderedNodes, sg...)
	orderedNodes = append(orderedNodes, sq...)
	orderedNodes = append(orderedNodes, ic...)
	orderedNodes = append(orderedNodes, ln...)
	return orderedNodes
}

func CreateDrawioConnectivityMapFile(network SquareTreeNodeInterface, outputFile string) error {
	newLayout(network).layout()
	allNodes := getAllNodes(network)
	data := &drawioData{
		fipXOffset,
		fipYOffset,
		miniIconXOffset,
		miniIconYOffset,
		miniIconSize,
		network.ID(),
		idsPrefix,
		network.HasVSIs(),
		network.HasVpes(),
		orderNodesForDrawio(allNodes)}
	return writeDrawioFile(data, outputFile)
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
