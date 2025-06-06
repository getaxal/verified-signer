package attestation

import "github.com/hf/nitrite"

// Response for the get attestation bytes (unverified and raw byte attestation)
type AttestationBytesResponse struct {
	Attestation string `json:"attestation"`
}

// Response for the get attestation as a document (after verification)
type AttestationDocResponse struct {
	AttestationDoc nitrite.Document `json:"attestation_doc"`
}
