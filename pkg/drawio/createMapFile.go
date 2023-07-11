package drawio

import (
	_ "embed"
	"fmt"
	"os"
	"text/template"
)

//go:embed connectivityMap.drawio.tmpl
var drawioTemplate string

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////
type line struct {
	Id int
	X1 int
	Y1 int
	X2 int
	Y2 int
}
type star struct {
	Id    int
	X     int
	Y     int
	color string
}

func (s *star) Red() bool {
	return s.color == "red"
}
func (s *star) Purple() bool {
	return s.color == "purple"
}
func (s *star) Yellow() bool {
	return s.color == "yellow"
}
func (s *star) Break() bool {
	return s.color == "break"
}

type debugData struct {
	Mesh  []line
	Stars []star
}

func updateDebugData(d *debugData, network TreeNodeInterface, matrix *layoutMatrix, lyO *layoutOverlap) {
	////////////////////////////////////////////////////////////////////////
	showMesh := false
	showOverlap := false

	// showMesh = true
	showOverlap = true
	id := 5000
	if showMesh {
		for _, r := range matrix.rows {
			d.Mesh = append(d.Mesh, line{id, 0, r.y(), network.Width(), r.y()})
			id = id + 10
		}
		for _, c := range matrix.cols {
			d.Mesh = append(d.Mesh, line{id, c.x(), 0, c.x(), network.Height()})
			id = id + 10
		}
	}
	if showOverlap {
		for y := 0; y < 5000; y++ {
			for x := 0; x < 5000; x++ {
				if lyO.overlapMap[y][x].hasOverlap {
					d.Stars = append(d.Stars, star{id, x * minSize, y * minSize, "red"})
				} else if lyO.overlapMap[y][x].pointAdded > 0 {
					d.Stars = append(d.Stars, star{id, x * minSize, y * minSize, "break"})
				} else if lyO.overlapMap[y][x].hasLine {
					d.Stars = append(d.Stars, star{id, x * minSize, y * minSize, "yellow"})
				} else if lyO.overlapMap[y][x].icon != nil {
					d.Stars = append(d.Stars, star{id, x * minSize, y * minSize, "purple"})
				}
				id = id + 10
			}
		}
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
	debugData
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
		getAllNodes(network),
		debugData{}}
	updateDebugData(&data.debugData, ly.network, ly.matrix, &ly.lyO)
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
