package report

import (
	"encoding/json"
	"io"

	"github.com/ghostroute/ghostroute/pkg/model"
)

// GenerateJSON writes formatted JSON representation of ScanResult to io.Writer.
func GenerateJSON(w io.Writer, sr *model.ScanResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sr)
}
