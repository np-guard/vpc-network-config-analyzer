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
	DEBUG // extended txt format with more details
)

const (
	writeFileMde = 0o600
)

type OutputUseCase int

const (
	VsiLevel          OutputUseCase = iota // connectivity between network interfaces and external ip-blocks
	DebugSubnet                            // connectivity per single subnet with nacl
	SubnetsLevel                           // connectivity between subnets (consider nacl + pgw)
	SubnetsLevelNoPGW                      // connectivity between subnets (consider nacl only)
)

type OutputGenerator struct {
	config         *CloudConfig
	outputGrouping bool
	useCase        OutputUseCase
	nodesConn      *VPCConnectivity
	subnetsConn    *VPCsubnetConnectivity
}

func NewOutputGenerator(c *CloudConfig, grouping bool, uc OutputUseCase) (*OutputGenerator, error) {
	res := &OutputGenerator{
		config:         c,
		outputGrouping: grouping,
		useCase:        uc,
	}

	if uc == VsiLevel {
		res.nodesConn = c.GetVPCNetworkConnectivity()
	}
	if uc == SubnetsLevel {
		subnetsConn, err := c.GetSubnetsConnectivity(true)
		if err != nil {
			return nil, err
		}
		res.subnetsConn = subnetsConn
	}

	return res, nil
}

func (o *OutputGenerator) Generate(f OutFormat, outFile string) (string, error) {
	var formatter OutputFormatter
	switch f {
	case JSON:
		formatter = &JSONoutputFormatter{}
	case Text:
		formatter = &TextoutputFormatter{}
	case MD:
		formatter = &MDoutputFormatter{}
	case DEBUG:
		formatter = &DebugoutputFormatter{}
	default:
		return "", errors.New("unsupported output format")
	}

	switch o.useCase {
	case VsiLevel:
		return formatter.WriteOutputVsiLevel(o.config, o.nodesConn, outFile, o.outputGrouping)
	case DebugSubnet:
		return formatter.WriteOutputDebugSubnet(o.config, outFile)
	case SubnetsLevel:
		return formatter.WriteOutputSubnetLevel(o.subnetsConn, outFile)
	}
	return "", errors.New("unsupported useCase argument")
}

// OutputFormatter has several write functions per each use-case
type OutputFormatter interface {
	WriteOutputVsiLevel(c *CloudConfig, conn *VPCConnectivity, outFile string, grouping bool) (string, error)
	WriteOutputSubnetLevel(subnetsConn *VPCsubnetConnectivity, outFile string) (string, error)
	WriteOutputDebugSubnet(c *CloudConfig, outFile string) (string, error)
}
