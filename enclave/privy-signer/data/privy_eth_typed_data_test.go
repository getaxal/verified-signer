package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Canonical example from the EIP-712 spec. The expected digest is the
// well-known signed-message hash of this payload, cross-checkable with
// ethers.js TypedDataEncoder.hash / cast.
const eip712SpecTypedData = `{
	"types": {
		"EIP712Domain": [
			{"name": "name", "type": "string"},
			{"name": "version", "type": "string"},
			{"name": "chainId", "type": "uint256"},
			{"name": "verifyingContract", "type": "address"}
		],
		"Person": [
			{"name": "name", "type": "string"},
			{"name": "wallet", "type": "address"}
		],
		"Mail": [
			{"name": "from", "type": "Person"},
			{"name": "to", "type": "Person"},
			{"name": "contents", "type": "string"}
		]
	},
	"primaryType": "Mail",
	"domain": {
		"name": "Ether Mail",
		"version": "1",
		"chainId": 1,
		"verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
	},
	"message": {
		"from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
		"to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
		"contents": "Hello, Bob!"
	}
}`

const eip712SpecDigest = "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"

// Known EIP-191 vector: keccak256("\x19Ethereum Signed Message:\n9Some data")
const personalSignMessage = "Some data"
const personalSignDigest = "0x1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655"

func TestHashTypedDataSpecVector(t *testing.T) {
	digest, info, err := hashTypedData(eip712SpecTypedData)
	require.NoError(t, err)
	assert.Equal(t, eip712SpecDigest, digest)
	require.NotNil(t, info)
	assert.Equal(t, "Ether Mail", info.Name)
	assert.Equal(t, "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC", info.VerifyingContract)
	assert.Equal(t, "1", info.ChainID)
	assert.Equal(t, "Mail", info.PrimaryType)
}

func TestHashTypedDataInvalid(t *testing.T) {
	_, _, err := hashTypedData("")
	assert.Error(t, err)

	_, _, err = hashTypedData("not json")
	assert.Error(t, err)

	// valid JSON but no primaryType
	_, _, err = hashTypedData(`{"domain":{},"types":{},"message":{}}`)
	assert.Error(t, err)
}

func TestHashPersonalSignMessage(t *testing.T) {
	digest, err := hashPersonalSignMessage(personalSignMessage)
	require.NoError(t, err)
	assert.Equal(t, personalSignDigest, digest)

	_, err = hashPersonalSignMessage("")
	assert.Error(t, err)
}

func TestUserEthSignTypedDataRequestValidate(t *testing.T) {
	req := &UserEthSignTypedDataRequest{Method: "eth_signTypedData_v4"}
	req.Params.TypedData = eip712SpecTypedData

	require.NoError(t, req.ValidateTxRequest())

	signData := req.GetPrivySignData()
	assert.Equal(t, "secp256k1_sign", signData.Method)
	assert.Equal(t, eip712SpecDigest, signData.Params.Hash)
}

func TestUserEthSignTypedDataRequestWrongMethod(t *testing.T) {
	req := &UserEthSignTypedDataRequest{Method: "secp256k1_sign"}
	req.Params.TypedData = eip712SpecTypedData

	assert.Error(t, req.ValidateTxRequest())
}

func TestAxalEthSignTypedDataRequestValidate(t *testing.T) {
	req := &AxalEthSignTypedDataRequest{Method: "eth_signTypedData_v4"}
	req.Params.TypedData = eip712SpecTypedData

	// privy_id missing
	assert.Error(t, req.ValidateTxRequest())

	req.PrivyID = "did:privy:user123"
	require.NoError(t, req.ValidateTxRequest())

	signData := req.GetPrivySignData()
	assert.Equal(t, "secp256k1_sign", signData.Method)
	assert.Equal(t, eip712SpecDigest, signData.Params.Hash)
}

func TestUserEthPersonalSignRequestValidate(t *testing.T) {
	req := &UserEthPersonalSignRequest{Method: "personal_sign"}
	req.Params.Message = personalSignMessage

	require.NoError(t, req.ValidateTxRequest())

	signData := req.GetPrivySignData()
	assert.Equal(t, "secp256k1_sign", signData.Method)
	assert.Equal(t, personalSignDigest, signData.Params.Hash)
}

func TestAxalEthPersonalSignRequestValidate(t *testing.T) {
	req := &AxalEthPersonalSignRequest{Method: "personal_sign"}
	req.Params.Message = personalSignMessage

	// privy_id missing
	assert.Error(t, req.ValidateTxRequest())

	req.PrivyID = "did:privy:user123"
	require.NoError(t, req.ValidateTxRequest())

	signData := req.GetPrivySignData()
	assert.Equal(t, "secp256k1_sign", signData.Method)
	assert.Equal(t, personalSignDigest, signData.Params.Hash)
}
