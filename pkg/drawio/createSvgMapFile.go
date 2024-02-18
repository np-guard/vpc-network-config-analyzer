package drawio

import (
	_ "embed"
	"fmt"
	"os"
	"reflect"

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

func (data *svgData) FipXOffset() int      { return fipXOffset }
func (data *svgData) FipYOffset() int      { return fipYOffset }
func (data *svgData) MiniIconXOffset() int { return miniIconXOffset }
func (data *svgData) MiniIconYOffset() int { return miniIconYOffset }
func (data *svgData) MiniIconSize() int    { return miniIconSize }

// func (data *svgData) RootID() uint         { return data.rootID }
// func (data *svgData) IDsPrefix() string    { return idsPrefix }
func (data *svgData) ElementComment(tn TreeNodeInterface) string {
	return reflect.TypeOf(tn).Elem().Name() + " " + tn.Label()
}
func (data *svgData) AddF(a int, b float64) float64 { return float64(a) + b }
func (data *svgData) Add(a int, b int) int          { return a + b }
func (data *svgData) Add3(a, b, c int) int          { return a + b + c }
func (data *svgData) Half(a int) int                { return a / 2 }

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
