package vpcmodel

import (
	"errors"
)

type OutFormat int64

const (
	JSON OutFormat = iota
	Text
	MD
	CSV
	DRAWIO
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
			JSON:   "",
			Text:   "",
			MD:     "",
			CSV:    "",
			DRAWIO: "",
		},
	}
}

func (o *OutputGenerator) SetOutputFile(outFileName string, f OutFormat) {
	o.outputFiles[f] = outFileName
}

func (o *OutputGenerator) GetOutputFile(f OutFormat) string {
	return o.outputFiles[f]
}

func (o *OutputGenerator) Generate(f OutFormat) (string, error) {
	var formatter OutputFormatter
	switch f {
	case JSON:
		formatter = &JSONoutputFormatter{}
	case Text:
		formatter = &TextoutputFormatter{}
	case MD:
		formatter = &MDoutputFormatter{}
	case DRAWIO:
		formatter = &DrawioOutputFormatter{}
	default:
		return "", errors.New("unsupported output format")
	}
	return formatter.WriteOutput(o.config, o.conn, o.outputFiles[f])
}

type OutputFormatter interface {
	WriteOutput(c *CloudConfig, conn *VPCConnectivity, outFile string) (string, error)
}
