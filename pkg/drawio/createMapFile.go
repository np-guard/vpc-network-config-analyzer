package drawio

import (
	_ "embed"
	"fmt"
	"os"
	"text/template"
)

//go:embed connectivityMap.drawio.tmpl
var drawioTemplate string



type drawioData struct {
	IconSize   int
	FipXOffset int
	FipYOffset int
	VSIXOffset int
	VSIYOffset int
	VSISize    int
	RootID     int
	IDsPrefix  string
	// ShowNIIcon says if to display the NI as an NI image, or a VSI image
	// the rule is that if we have a vsi icon, then we display the NI icon as an NI image
	ShowNIIcon bool
	Nodes      []TreeNodeInterface
}

func CreateDrawioConnectivityMapFile(network SquareTreeNodeInterface, outputFile string) error {
	ly := newLayout(network)
	ly.layout()
	data := &drawioData{
		iconSize,
		fipXOffset,
		fipYOffset,
		vsiXOffset,
		vsiYOffset,
		vsiIconSize,
		rootID,
		idsPrefix,
		network.HasVSIs(),
		getAllNodes(network)}
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
