package vpcmodel

import (
	"encoding/json"
	"errors"
	"os"
)

type OutFormat int64

const (
	JSON OutFormat = iota
	Text
	MD
	CSV
)

const (
	writeFileMde = 0o600
)

type OutputGenerator struct {
	config      *CloudConfig
	conn        *VPCConnectivity
	outputFiles map[OutFormat]string
}

func NewOutputGenerator(c *CloudConfig, conn *VPCConnectivity) *OutputGenerator {
	return &OutputGenerator{
		config: c,
		conn:   conn,
		outputFiles: map[OutFormat]string{
			JSON: "",
			Text: "",
			MD:   "",
			CSV:  "",
		},
	}
}

func (o *OutputGenerator) SetOutputFile(outFileName string, f OutFormat) {
	o.outputFiles[f] = outFileName
}

func (o *OutputGenerator) Generate(f OutFormat) (string, error) {
	var formatter OutputFormatter
	switch f {
	case JSON:
		formatter = &JSONoutputFormatter{}
	case Text:
		formatter = &TextoutputFormatter{}
	default:
		return "", errors.New("unsupported output format")
	}
	return formatter.WriteOutput(o.config, o.conn, o.outputFiles[f])
}

type OutputFormatter interface {
	WriteOutput(c *CloudConfig, conn *VPCConnectivity, outFile string) (string, error)
}

type JSONoutputFormatter struct {
}

type connLine struct {
	Src  Node   `json:"src"`
	Dst  Node   `json:"dst"`
	Conn string `json:"conn"`
}

type architecture struct {
	Nodes    []map[string]string
	NodeSets []map[string]string
	Filters  []map[string]string
	Routers  []map[string]string
}

type allInfo struct {
	Arch         architecture `json:"architecture"`
	Connectivity []connLine   `json:"connectivity"`
}

func writeToFile(content, fileName string) error {
	if fileName != "" {
		return os.WriteFile(fileName, []byte(content), writeFileMde)
	}
	return nil
}

func (j *JSONoutputFormatter) WriteOutput(c *CloudConfig, conn *VPCConnectivity, outFile string) (string, error) {
	all := allInfo{}

	connLines := []connLine{}

	for src, srcMap := range conn.AllowedConnsCombined {
		for dst, conn := range srcMap {
			if conn.IsEmpty() {
				continue
			}
			connLines = append(connLines, connLine{Src: src, Dst: dst, Conn: conn.String()})
		}
	}
	all.Connectivity = connLines
	all.Arch = architecture{
		Nodes:    []map[string]string{},
		NodeSets: []map[string]string{},
		Filters:  []map[string]string{},
		Routers:  []map[string]string{},
	}
	for _, n := range c.Nodes {
		all.Arch.Nodes = append(all.Arch.Nodes, n.DetailsMap())
	}
	for _, n := range c.NodeSets {
		all.Arch.NodeSets = append(all.Arch.NodeSets, n.DetailsMap())
	}
	for _, fl := range c.FilterResources {
		all.Arch.Filters = append(all.Arch.Filters, fl.DetailsMap()...)
	}
	for _, r := range c.RoutingResources {
		all.Arch.Routers = append(all.Arch.Routers, r.DetailsMap())
	}

	res, err := json.MarshalIndent(all, "", "    ")
	if err != nil {
		return "", err
	}
	resStr := string(res)
	err = writeToFile(resStr, outFile)
	return resStr, err
}

type TextoutputFormatter struct {
}

func (t *TextoutputFormatter) WriteOutput(c *CloudConfig, conn *VPCConnectivity, outFile string) (string, error) {
	out := conn.String()
	err := writeToFile(out, outFile)
	return out, err
}
