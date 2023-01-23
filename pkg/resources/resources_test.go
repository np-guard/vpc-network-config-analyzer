package resources

import (
	_ "embed"
	"os"
	"strings"
	"testing"
)

//go:embed nwacl_1.json
var nwacl1 []byte

//go:embed nwacl_2.json
var nwacl2 []byte

//go:embed nwacl_3.json
var nwacl3 []byte

func TestBasic(t *testing.T) {
	naclExamples := [][]byte{nwacl1, nwacl2, nwacl3}
	for index, nwacl := range naclExamples {
		naclObj := JsonNaclToObject(nwacl)
		naclJson, err := ObjectNaclToJson(naclObj)
		if err != nil {
			t.Errorf("error ObjectNaclToJson: %v", err)
		}
		if getJsonStr(naclJson) != getJsonStr(nwacl) {
			os.WriteFile("actual.json", naclJson, 0600)
			t.Errorf("test index %d: error naclJson not equal to original json string", index)
		}
	}
}

func getJsonStr(b []byte) string {
	res := string(b)
	res = strings.ReplaceAll(res, " ", "")
	res = strings.ReplaceAll(res, "\n", "")
	return res
}
