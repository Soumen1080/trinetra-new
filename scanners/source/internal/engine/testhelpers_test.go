package engine

import (
	"encoding/json"
	"errors"

	"github.com/trinetra/cbom-go/cbom"
	"github.com/trinetra/cbom-go/scannerapi"
)

// unmarshalDocument reads a published CBOM back for assertion.
//
// Tests read the file from the artifact store rather than the in-memory
// document, so they verify what was actually published — the bytes an ingest
// stage would receive.
func unmarshalDocument(raw []byte) (cbom.Document, error) {
	var doc cbom.Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return doc, err
	}
	return doc, nil
}

// asScanError unwraps a client-safe scanner error.
func asScanError(err error, target **scannerapi.ScanError) bool {
	return errors.As(err, target)
}
