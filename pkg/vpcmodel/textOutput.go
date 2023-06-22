package vpcmodel

type TextoutputFormatter struct {
}

func (t *TextoutputFormatter) WriteOutput(c *CloudConfig, conn *VPCConnectivity, outFile string) (string, error) {
	out := conn.String()
	err := WriteToFile(out, outFile)
	return out, err
}
