// +build gofuzz

package api

func Fuzz(data []byte) int {
	if _, err := parseGPSData(string(data)); err != nil {
		return 0
	}

	return 1
}
