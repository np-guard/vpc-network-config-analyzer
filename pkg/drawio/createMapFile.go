package drawio

import (
	_ "embed"
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
	ShowNIIcon bool
	Nodes      []TreeNodeInterface
}

func CreateDrawioConnectivityMapFile(network SquareTreeNodeInterface, outputFile string) {
	newLayout(network).layout()
	data := &drawioData{
		iconSize,
		fipXOffset,
		fipYOffset,
		vsiXOffset,
		vsiYOffset,
		vsiIconSize,
		hasVsiIcon(network),
		getAllNodes(network)}
	writeDrawioFile(data, outputFile)
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
	defer func() error {
		if err = fo.Close(); err != nil {
			return err
		}
		return nil
	}()
	err = tmpl.Execute(fo, data)
	if err != nil {
		return err
	}
	return nil
}
