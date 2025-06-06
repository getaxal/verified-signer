package router

import (
	"encoding/binary"
	"net/http"
	"strconv"

	"github.com/getaxal/verified-signer/enclave"
	"github.com/getaxal/verified-signer/enclave/attestation"
	privydata "github.com/getaxal/verified-signer/enclave/privy-signer/data"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Handler for fetching the unverified raw bytes of the attestation
func GetAttestationBytesHandler(c *gin.Context) {
	nonce, err := strconv.ParseUint(c.Param("nonce"), 10, 64)

	if err != nil {
		log.Error("Invalid nonce provided, could not parse to int")
		resp := privydata.Message{
			Message: "nonce is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, nonce)
	attBytes, err := attestation.Attest(buf, []byte{}, []byte{})

	if err != nil {
		log.Error("Unable to generate attestation")
		resp := privydata.Message{
			Message: "Internal server error",
		}
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	attString := enclave.MarshalBytesToJSONHex(attBytes)

	resp := attestation.AttestationBytesResponse{
		Attestation: attString,
	}

	c.JSON(http.StatusBadRequest, resp)
}

// Handler for fetching the verified attestation doc
func GetAttestationDocHandler(c *gin.Context) {
	nonce, err := strconv.ParseUint(c.Param("nonce"), 10, 64)

	if err != nil {
		log.Error("Invalid nonce provided, could not parse to int")
		resp := privydata.Message{
			Message: "nonce is invalid",
		}
		c.JSON(http.StatusBadRequest, resp)
		return
	}

	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, nonce)
	doc, err := attestation.AttestAndVerify(buf, []byte{}, []byte{})

	if err != nil {
		log.Error("Unable to generate attestation")
		resp := privydata.Message{
			Message: "Internal server error",
		}
		c.JSON(http.StatusInternalServerError, resp)
		return
	}

	resp := attestation.AttestationDocResponse{
		AttestationDoc: *doc,
	}

	c.JSON(http.StatusBadRequest, resp)
}
