package poc

import (
	"encoding/json"
)

// Model for puf authentication program output
type PufAuthResult struct {
	Kty string `json:"kty,omitempty"`
	Use string `json:"use,omitempty"`
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid,omitempty"`
	X   string `json:"x,omitempty"`
}

// Model for newDID method input
type NewDIDArgs struct {
	Keys []KeyTypePurpose `json:"keys,omitempty"`
	Name string           `json:"name,omitempty"`
}
type TestingCallResult struct {
	result json.RawMessage `json:"didDoc,omitempty"`
}
// Model for newDID method output
type NewDIDResult struct {
	DIDDoc json.RawMessage `json:"didDoc,omitempty"`
}

// Model keytype/purpose pair
type KeyTypePurpose struct {
	KeyType KeyTypeModel `json:"keyType,omitempty"`
	Purpose string       `json:"purpose,omitempty"`
}

// Model keytype
type KeyTypeModel struct {
	Type  string `json:"keytype,omitempty"`
	Attrs []string `json:"attrs,omitempty"`
}

// Model for enrolDevice method input
type DoDeviceEnrolmentArgs struct {
	Url      string    `json:"url,omitempty"`
	TheirDID string    `json:"theirDID,omitempty"`
	IdProofs []IdProof `json:"idProofs,omitempty"`
}

// Model for enrolDevice method output
type DoDeviceEnrolmentResult struct {
	Credential    json.RawMessage `json:"credential,omitempty"`
	CredStorageId string          `json:"credStorageId,omitempty"`
}

// Model for idProof
type IdProof struct {
	AttrName  string          `json:"attrName,omitempty"`
	AttrValue interface{}     `json:"attrValue,omitempty"`
	ProofData json.RawMessage `json:"proofData,omitempty"`
}

// Model for GenerateVP method input
type GenerateVPArgs struct {
	CredId string `json:"credId,omitempty"` //TODO UMU: How do we decide which credential is gonna be presented?
}

// Model for GenerateVP method output
type GenerateVPResult struct {
	Credential json.RawMessage `json:"credential,omitempty"` //TODO UMU: Change to  maybe For now we present a complete credential?
}

// Model for AcceptEnrolment method input
type AcceptEnrolmentArgs struct {
	IdProofs []IdProof `json:"idProofs,omitempty"`
}

// Model for AcceptEnrolment method output
type AcceptEnrolmentResult struct {
	Credential json.RawMessage `json:"credential,omitempty"`
}

// Model for VerfyCredential method input
type VerifyCredentialArgs struct {
	CredentialString string `json:"credential,omitempty"`
}

// Model for VerifyCredential method output
type VerifyCredentialResult struct {
	Result bool `json:"result,omitempty"`

	Error string `json:"error,omitempty"`
}