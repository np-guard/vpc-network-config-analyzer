package vpcmodel

import (
	"errors"
	"os"
)

type OutFormat int64

const (
	JSON OutFormat = iota
	Text
	MD
	CSV
	DRAWIO
	ARCHDRAWIO
	Debug // extended txt format with more details
)

const (
	writeFileMde = 0o600
)

type OutputUseCase int

const (
	AllEndpoints    OutputUseCase = iota // connectivity between network interfaces and external ip-blocks
	SingleSubnet                         // connectivity per single subnet with nacl
	AllSubnets                           // connectivity between subnets (consider nacl + pgw)
	AllSubnetsNoPGW                      // connectivity between subnets (consider nacl only)
)

type OutputGenerator struct {
	config         *VPCConfig
	outputGrouping bool
	useCase        OutputUseCase
	nodesConn      *VPCConnectivity
	subnetsConn    *VPCsubnetConnectivity
}

func NewOutputGenerator(c *VPCConfig, grouping bool, uc OutputUseCase, archOnly bool) (*OutputGenerator, error) {
	res := &OutputGenerator{
		config:         c,
		outputGrouping: grouping,
		useCase:        uc,
	}
	if !archOnly {
		if uc == AllEndpoints {
			nodesConn, err := c.GetVPCNetworkConnectivity(grouping)
			if err != nil {
				return nil, err
			}
			res.nodesConn = nodesConn
		}
		if uc == AllSubnets {
			subnetsConn, err := c.GetSubnetsConnectivity(true, grouping)
			if err != nil {
				return nil, err
			}
			res.subnetsConn = subnetsConn
		}
	}
	// todo: add for diff
	return res, nil
}

func (o *OutputGenerator) Generate(f OutFormat, outFile string) (string, error) {
	var formatter OutputFormatter
	switch f {
	case JSON:
		formatter = &JSONoutputFormatter{}
	case Text:
		formatter = &TextOutputFormatter{}
	case MD:
		formatter = &MDoutputFormatter{}
	case DRAWIO:
		formatter = &DrawioOutputFormatter{}
	case ARCHDRAWIO:
		formatter = &ArchDrawioOutputFormatter{}
	case Debug:
		formatter = &DebugOutputFormatter{}
	default:
		return "", errors.New("unsupported output format")
	}

	return formatter.WriteOutput(o.config, o.nodesConn, o.subnetsConn, outFile, o.outputGrouping, o.useCase)
}

type OutputFormatter interface {
	WriteOutput(c *VPCConfig, conn *VPCConnectivity, subnetsConn *VPCsubnetConnectivity, outFile string,
		grouping bool, uc OutputUseCase) (string, error)
}

func writeOutput(out, file string) (string, error) {
	err := WriteToFile(out, file)
	return out, err
}

func WriteToFile(content, fileName string) error {
	if fileName != "" {
		return os.WriteFile(fileName, []byte(content), writeFileMde)
	}
	return nil
}
