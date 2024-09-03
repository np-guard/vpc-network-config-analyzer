/*
Copyright 2023- IBM Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package drawio

import (
	"bytes"
	_ "embed"
	"reflect"
	"sort"
	"strings"
	"text/template"

	"github.com/np-guard/cloud-resource-collector/pkg/common"
)

const (
	drawioTableSep = "&#xa;"
	SvgTableSep    = "<br/>"
)

type FileFormat int64

const (
	FileDRAWIO FileFormat = iota
	FileSVG
	FileHTML
)

//go:embed connectivityMap.drawio.tmpl
var drawioTemplate string

//go:embed connectivityMap.svg.tmpl
var svgTemplate string

var formatsTemplate = map[FileFormat]string{
	FileDRAWIO: drawioTemplate,
	FileSVG:    svgTemplate,
	FileHTML:   svgTemplate,
}

type ExplanationEntry struct {
	Src, Dst TreeNodeInterface
	Text     string
}

type templateData struct {
	templateStyles
	Width        int
	Height       int
	rootID       uint
	Nodes        []TreeNodeInterface
	DebugPoints  []debugPoint
	Relations    string
	Explanations []ExplanationEntry
	clickable    map[TreeNodeInterface]bool
	svgNames     map[TreeNodeInterface]string
	IsHTML       bool
}

func newTemplateData(network SquareTreeNodeInterface, explanations []ExplanationEntry,
	provider common.Provider, interactive bool) *templateData {
	orderedNodes := orderNodesForTemplate(network)
	data := &templateData{
		newTemplateStyles(orderedNodes, provider),
		network.Width(),
		network.Height(),
		network.ID(),
		orderedNodes,
		network.DebugPoints(),
		"",
		explanations,
		map[TreeNodeInterface]bool{},
		map[TreeNodeInterface]string{},
		interactive,
	}
	if interactive {
		data.setNodesNames(network)
		data.setNodesRelations(network)
		for _, e := range data.Explanations {
			data.clickable[e.Src] = true
			data.clickable[e.Dst] = true
		}
		data.clickable[network.(*NetworkTreeNode).publicNetwork] = true
	}
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
	return reflect.TypeOf(tn).Elem().Name() + " " + treeNodeName(tn)
}
func (data *templateData) NodeName(tn TreeNodeInterface) string {
	return data.svgNames[tn]
}
func (data *templateData) SvgLabel(tn TreeNodeInterface) string {
	if tn.IsSquare() && len(tn.labels()) == 1 {
		// this case is for vertical aliment fo the square name, I failed to do it at the html
		return SvgTableSep + joinLabels(tn.labels(), SvgTableSep)
	}
	return joinLabels(tn.labels(), SvgTableSep)
}

const (
	maxConnLabelSize = 8
	threeDots        = "..."
)

func (data *templateData) SvgShortLabel(tn TreeNodeInterface) string {
	// the connection label is created in another package,
	// so, instead of creating a short version, we edit the long version here:
	label := data.SvgLabel(tn)
	label = strings.ReplaceAll(label, "protocol:", "")
	if !strings.Contains(label, "src-ports:") {
		label = strings.ReplaceAll(label, "dst-ports:", "")
	}
	if len(label) > maxConnLabelSize {
		return label[0:maxConnLabelSize-len(threeDots)] + threeDots
	}
	return label
}

func (data *templateData) DrawioLabel(tn TreeNodeInterface) string {
	return joinLabels(tn.labels(), drawioTableSep)
}
func (data *templateData) Clickable(tn TreeNodeInterface) bool {
	return data.clickable[tn]
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

// orderNodesForTemplate() sort the nodes for the drawio/svg/html canvas
// the order in the canvas are set by the order in the drawio/svg/html file
// (the last in the file will be on top in the canvas)
// for clicking on a node, it must not be behind another node
// 1. we put the lines at the top so they will overlap the icons
// 2. we put the icons above the squares
// 3. we bucket sort the squares, and order them by parent-child order
// 4. we also sort the groupSquare by size
func orderNodesForTemplate(network SquareTreeNodeInterface) []TreeNodeInterface {
	squareOrders := []SquareTreeNodeInterface{
		&NetworkTreeNode{},
		&PublicNetworkTreeNode{},
		&CloudTreeNode{},
		&RegionTreeNode{},
		&VpcTreeNode{},
		&GroupSubnetsSquareTreeNode{},
		&ZoneTreeNode{},
		&SubnetTreeNode{},
		&GroupSquareTreeNode{},
		&SGTreeNode{},
		&PartialSGTreeNode{},
	}
	squaresBuckets := map[reflect.Type][]TreeNodeInterface{}
	for _, tn := range getAllSquaresAsTNs(network) {
		e := reflect.TypeOf(tn).Elem()
		squaresBuckets[e] = append(squaresBuckets[e], tn)
	}
	for _, square := range []SquareTreeNodeInterface{
		&GroupSquareTreeNode{},
		&GroupSubnetsSquareTreeNode{},
	} {
		nodes := squaresBuckets[reflect.TypeOf(square).Elem()]
		sort.Slice(nodes, func(i, j int) bool {
			return nodes[i].Width() > nodes[j].Width()
		})
	}
	orderedNodes := []TreeNodeInterface{}
	for _, t := range squareOrders {
		orderedNodes = append(orderedNodes, squaresBuckets[reflect.TypeOf(t).Elem()]...)
	}
	orderedNodes = append(orderedNodes, getAllIconsAsTNs(network)...)
	orderedNodes = append(orderedNodes, getAllLinesAsTNs(network)...)
	return orderedNodes
}

func CreateDrawioConnectivityMap(
	network SquareTreeNodeInterface, subnetMode bool,
	format FileFormat, explanations []ExplanationEntry, provider common.Provider) (string, error) {
	newLayout(network, subnetMode).layout()
	data := newTemplateData(network, explanations, provider, format == FileHTML)
	tmpl, err := template.New("diagram").Parse(formatsTemplate[format])
	if err != nil {
		return "", err
	}
	oBuffer := bytes.NewBufferString("")
	err = tmpl.Execute(oBuffer, data)

	return oBuffer.String(), err
}
