// Package yamlstrict decodes security-sensitive YAML configuration with a
// single-document, known-field contract.
package yamlstrict

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Decode decodes exactly one non-empty YAML document and rejects fields that
// are not represented by the destination's yaml tags. yaml.v3 also rejects
// duplicate mapping keys while decoding into Go values.
func Decode(data []byte, destination any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("YAML document is required")
		}
		return err
	}

	var extra yaml.Node
	err := decoder.Decode(&extra)
	if err == nil {
		return fmt.Errorf("multiple YAML documents are not allowed")
	}
	if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
