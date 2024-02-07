package drawio

import (
	_ "embed"
	"fmt"
	"os"

	// "reflect"
	"text/template"
)

//go:embed connectivityMap.svg.tmpl
var svgTemplate string

type svgData struct {
	drawioStyles
	Width       int
	Height      int
	Nodes       []TreeNodeInterface
	DebugPoints []debugPoint
}

func NewSvgData(network SquareTreeNodeInterface) *svgData {
	return &svgData{
		newDrawioStyles(getAllNodes(network)),
		network.Width(),
		network.Height(),
		getAllNodes(network),
		network.DebugPoints(),
	}
}

// func (data *drawioData) FipXOffset() int      { return fipXOffset }
// func (data *drawioData) FipYOffset() int      { return fipYOffset }
// func (data *drawioData) MiniIconXOffset() int { return miniIconXOffset }
// func (data *drawioData) MiniIconYOffset() int { return miniIconYOffset }
// func (data *drawioData) MiniIconSize() int    { return miniIconSize }
// func (data *drawioData) RootID() uint         { return data.rootID }
// func (data *drawioData) IDsPrefix() string    { return idsPrefix }
// func (data *drawioData) ElementComment(tn TreeNodeInterface) string {
// 	return reflect.TypeOf(tn).Elem().Name() + " " + tn.Label()
// }
func (data *svgData) Add( a int ,b float64) float64         { return float64(a)+b }

func (data *svgData) AX(tn TreeNodeInterface) int {
	x, _ := absoluteGeometry(tn)
	return x
}
func (data *svgData) AY(tn TreeNodeInterface) int {
	_, y := absoluteGeometry(tn)
	return y
}


func writeSvgFile(network SquareTreeNodeInterface, outputFile string) error {
	data := NewSvgData(network)
	tmpl, err := template.New("connectivityMap.svg.tmpl").Parse(svgTemplate)
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
