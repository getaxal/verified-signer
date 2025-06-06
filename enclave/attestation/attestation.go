package attestation

import (
	"errors"
	"time"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	log "github.com/sirupsen/logrus"

	"github.com/hf/nitrite"
)

// Attests to user data, nonce and and the pubkey of the enclave.
func Attest(nonce, userData, publicKey []byte) ([]byte, error) {
	log.Info("Starting attestation process")
	sess, err := nsm.OpenDefaultSession()
	defer sess.Close()

	if nil != err {
		log.Errorf("Unable to open NSM session with error: %v", err)
		return nil, err
	}

	log.Info("Sending attestation request")
	res, err := sess.Send(&request.Attestation{
		Nonce:     nonce,
		UserData:  userData,
		PublicKey: publicKey,
	})

	if nil != err {
		log.Errorf("Unable to send attestation req with error: %v", err)
		return nil, err
	}

	if "" != res.Error {
		log.Errorf("Error with attestation doc: %s", string(res.Error))
		return nil, errors.New(string(res.Error))
	}

	if nil == res.Attestation || nil == res.Attestation.Document {
		log.Errorf("NSM device did not return an attestation")
		return nil, errors.New("NSM device did not return an attestation")
	}

	return res.Attestation.Document, nil
}

func decryptedAttestationDoc(attestationRes []byte, verificationOptions nitrite.VerifyOptions) (*nitrite.Document, error) {
	log.Info("Starting verification process")
	res, err := nitrite.Verify(attestationRes, verificationOptions)

	if err != nil {
		log.Errorf("Error verifying doc with err: %v", err)
		return nil, err
	}

	return (*res).Document, nil
}

// Attests to user data, nonce and and the pubkey of the enclave. Returns the bytes of the attestation doc that need to be decrypted according to the steps listed here: https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md#31-cose-and-cbor
func AttestAndVerify(nonce, userData, publicKey []byte) (*nitrite.Document, error) {
	res, err := Attest(nonce, userData, publicKey)

	if err != nil {
		return nil, err
	}

	doc, err := decryptedAttestationDoc(res, nitrite.VerifyOptions{
		CurrentTime: time.Now(),
	})

	if err != nil {
		return nil, err
	}

	return doc, nil

}
