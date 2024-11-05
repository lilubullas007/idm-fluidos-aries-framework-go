/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package poc

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vcwallet"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/didexchange"
	issuecredentialsvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/issuecredential"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/mediator"
	outofbandSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofband"
	oobv2 "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/outofbandv2"
	presentproofSvc "github.com/hyperledger/aries-framework-go/pkg/didcomm/protocol/presentproof"
	mockoutofbandv2 "github.com/hyperledger/aries-framework-go/pkg/internal/gomocks/client/outofbandv2"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ldtestutil"
	mockdidexchange "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/didexchange"
	mockissuecredential "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/issuecredential"
	mockmediator "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/mediator"
	mockoutofband "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/outofband"
	mockpresentproof "github.com/hyperledger/aries-framework-go/pkg/mock/didcomm/protocol/presentproof"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	mockstore "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/square/go-jose/v3/json"
	"github.com/stretchr/testify/require"

	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/internal/testdata"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/stretchr/testify/assert"

	"testing"
)

const (
	sampleDIDName = "sampleDIDName"
	sampleCredId  = "http://example.edu/credentials/1872"
	sampleUser1   = "sampleUser1"
	samplePass    = "fakepassphrase"
	sampleDID     = "did:example:123"
)

func TestNewDID(t *testing.T) {

	// Success: DID successfully created
	t.Run("test newDID method - success", func(t *testing.T) {
		purposeAuth := KeyTypePurpose{Purpose: "Authentication", KeyType: KeyTypeModel{Type: ed25519VerificationKey2018}}
		purposeAssertion := KeyTypePurpose{Purpose: "AssertionMethod", KeyType: KeyTypeModel{Type: bls12381G1Key2022, Attrs: []string{"2"}}}

		newDIDArgs := NewDIDArgs{Keys: []KeyTypePurpose{purposeAuth, purposeAssertion}, Name: sampleDIDName}

		var l bytes.Buffer
		reader, err := getReader(newDIDArgs)

		require.NotNil(t, reader)
		require.NoError(t, err)

		vcwalletCommand := vcwallet.New(newMockProvider(t), &vcwallet.Config{})
		require.NotNil(t, vcwalletCommand)
		require.NoError(t, err)

		vdrCommand, err := vdr.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      &mockvdr.MockVDRegistry{}, // Mock VDRegistry
		})
		require.NotNil(t, vdrCommand)
		require.NoError(t, err)

		command, err := New(vdrCommand, vcwalletCommand)
		require.NoError(t, err)

		err = command.NewDID(&l, reader)

		require.NoError(t, err)
		require.NotNil(t, command)

		var response NewDIDResult

		err = json.NewDecoder(&l).Decode(&response)
		require.NoError(t, err)

		// fmt.Println(response)

		var didDoc map[string]interface{}

		// Decode DIDDoc content
		err = json.Unmarshal(response.DIDDoc, &didDoc)
		require.NoError(t, err)

		prettyDidDoc, err := json.MarshalIndent(didDoc, "", "  ")
		require.NoError(t, err)

		fmt.Printf("DID Document: %s\n", string(prettyDidDoc))

		fmt.Println()
		//require.Equal(t, 5, len(handlers))
	})

	// Error case: empty keys
	t.Run("test newDID method - empty keys", func(t *testing.T) {
		newDIDArgs := NewDIDArgs{Keys: nil, Name: sampleDIDName}

		var l bytes.Buffer
		reader, err := getReader(newDIDArgs)
		require.NoError(t, err)

		vcwalletCommand := vcwallet.New(newMockProvider(t), &vcwallet.Config{})
		require.NotNil(t, vcwalletCommand)

		vdrCommand, err := vdr.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      &mockvdr.MockVDRegistry{},
		})
		require.NoError(t, err)

		command, err := New(vdrCommand, vcwalletCommand)
		require.NoError(t, err)

		err = command.NewDID(&l, reader)

		require.Error(t, err)
		require.Contains(t, err.Error(), "keys is mandatory")
	})

	// Error case: invalid key type
	t.Run("test newDID method - invalid key type", func(t *testing.T) {
		purposeAuth := KeyTypePurpose{Purpose: "Authentication", KeyType: KeyTypeModel{Type: "invalidKeyType"}}
		newDIDArgs := NewDIDArgs{Keys: []KeyTypePurpose{purposeAuth}, Name: sampleDIDName}

		var l bytes.Buffer
		reader, err := getReader(newDIDArgs)
		require.NoError(t, err)

		vcwalletCommand := vcwallet.New(newMockProvider(t), &vcwallet.Config{})
		require.NotNil(t, vcwalletCommand)

		vdrCommand, err := vdr.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      &mockvdr.MockVDRegistry{},
		})
		require.NoError(t, err)

		command, err := New(vdrCommand, vcwalletCommand)
		require.NoError(t, err)

		err = command.NewDID(&l, reader)

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key type")
	})

	/*t.Run("test new command - did store error", func(t *testing.T) {
		cmd, err := New(&mockprovider.Provider{
			StorageProviderValue: &mockstore.MockStoreProvider{
				ErrOpenStoreHandle: fmt.Errorf("error opening the store"),
			},
		})

		require.Error(t, err)
		require.Contains(t, err.Error(), "new did store")
		require.Nil(t, cmd)
	})*/
}

func Test_SignVerifyJWTContent(t *testing.T) {

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = getMockDIDKeyVDR()

	// Initialize cryptographic provider
	tcrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	mockctx.CryptoValue = tcrypto

	vcwalletCommand := vcwallet.New(mockctx, &vcwallet.Config{})
	require.NotNil(t, vcwalletCommand)

	vdrCommand, err := vdr.New(mockctx)
	require.NotNil(t, vdrCommand)
	require.NoError(t, err)

	// Command instance
	command, err := New(vdrCommand, vcwalletCommand)
	require.NoError(t, err)

	token, lock1 := command.unlockWallet(t, command.walletuid, command.walletpass)

	var b bytes.Buffer

	reqCreateKey, err := getReader(&vcwallet.CreateKeyPairRequest{
		WalletAuth: vcwallet.WalletAuth{UserID: command.walletuid, Auth: token},
		KeyType:    kms.ED25519Type,
	})
	require.NoError(t, err)

	err = command.vcwalletcommand.CreateKeyPair(&b, reqCreateKey)
	require.NoError(t, err)

	var keyPairResponse vcwallet.CreateKeyPairResponse
	require.NoError(t, json.NewDecoder(&b).Decode(&keyPairResponse))

	pubKey, err := base64.RawURLEncoding.DecodeString(keyPairResponse.PublicKey)
	require.NoError(t, err)

	_, didKID := fingerprint.CreateDIDKeyByCode(fingerprint.ED25519PubKeyMultiCodec, pubKey)
	parts := strings.Split(didKID, "#")
	currentDID := parts[0]
	currentKeyID := parts[1]

	b.Reset()
	lock1()

	command.currentDID = currentDID
	command.currentKeyPair = keyPairResponse
	command.currentKeyPair.KeyID = currentKeyID

	content := map[string]interface{}{
		"name":      "John Doe",
		"attrName":  "DID",
		"attrValue": command.currentDID,
	}

	// Success: JWT content successfully signed and verified
	t.Run("test Sign and Verify JWT content - success", func(t *testing.T) {
		contentBytes, err := json.Marshal(content)
		require.NoError(t, err)

		signRequest, err := getReader(SignJWTContentArgs{
			Content: contentBytes,
		})
		require.NoError(t, err)

		var signResponse bytes.Buffer
		err = command.SignJWTContent(&signResponse, signRequest)
		require.NoError(t, err)

		// Verify JWT content
		var jwtSignResponse SignJWTContentResult
		err = json.Unmarshal(signResponse.Bytes(), &jwtSignResponse)
		require.NoError(t, err)

		verifyRequest, err := getReader(VerifyJWTContentArgs{
			JWT: jwtSignResponse.SignedJWTContent,
		})
		require.NoError(t, err)

		var verifyResponse bytes.Buffer
		err = command.VerifyJWTContent(&verifyResponse, verifyRequest)
		require.NoError(t, err)

		var jwtVerifyResponse vcwallet.VerifyJWTResponse
		err = json.Unmarshal(verifyResponse.Bytes(), &jwtVerifyResponse)
		require.NoError(t, err)

		if jwtVerifyResponse.Verified {
			fmt.Println("JWT content verified")
		}
	})

	// Error case: invalid wallet token
	t.Run("test SignJWTContent - invalid wallet token", func(t *testing.T) {
		invalidToken := "incorrect-token"
		reqCreateKey, err := getReader(&vcwallet.CreateKeyPairRequest{
			WalletAuth: vcwallet.WalletAuth{UserID: command.walletuid, Auth: invalidToken},
			KeyType:    kms.ED25519Type,
		})
		require.NoError(t, err)

		var b bytes.Buffer
		err = command.vcwalletcommand.CreateKeyPair(&b, reqCreateKey)

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid auth token")
	})

	// Error case: malformed JWT
	t.Run("test VerifyJWTContent - malformed JWT", func(t *testing.T) {
		malformedJWT := "not-a-jwt-token"
		verifyRequest, err := getReader(VerifyJWTContentArgs{
			JWT: malformedJWT,
		})
		require.NoError(t, err)

		var verifyResponse bytes.Buffer
		err = command.VerifyJWTContent(&verifyResponse, verifyRequest)

		var jwtVerifyResponse vcwallet.VerifyJWTResponse
		err = json.Unmarshal(verifyResponse.Bytes(), &jwtVerifyResponse)
		require.NoError(t, err)

		require.False(t, jwtVerifyResponse.Verified)
		require.Contains(t, jwtVerifyResponse.Error, "jwt verification failed: JWT of compacted JWS form is supported only")
	})

	// Error case: tampered JWT
	t.Run("test VerifyJWTContent - tampered JWT", func(t *testing.T) {
		contentBytes, err := json.Marshal(content)
		require.NoError(t, err)

		var signResponse bytes.Buffer
		signRequest, err := getReader(SignJWTContentArgs{
			Content: contentBytes,
		})
		require.NoError(t, err)

		err = command.SignJWTContent(&signResponse, signRequest)
		require.NoError(t, err)

		var jwtSignResponse SignJWTContentResult
		err = json.Unmarshal(signResponse.Bytes(), &jwtSignResponse)
		require.NoError(t, err)

		// Manipulate signed JWT
		tamperedJWT := jwtSignResponse.SignedJWTContent + "tamper"

		verifyRequest, err := getReader(VerifyJWTContentArgs{
			JWT: tamperedJWT,
		})
		require.NoError(t, err)

		var verifyResponse bytes.Buffer
		err = command.VerifyJWTContent(&verifyResponse, verifyRequest)

		var jwtVerifyResponse vcwallet.VerifyJWTResponse
		err = json.Unmarshal(verifyResponse.Bytes(), &jwtVerifyResponse)
		require.NoError(t, err)

		require.False(t, jwtVerifyResponse.Verified)
		require.Contains(t, jwtVerifyResponse.Error, "jwt verification failed")
	})

}

func Test_SignVerifyJWT(t *testing.T) {

	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = getMockDIDKeyVDR()

	// Initialize cryptographic provider
	tcrypto, err := tinkcrypto.New()
	require.NoError(t, err)

	mockctx.CryptoValue = tcrypto

	vcwalletCommand := vcwallet.New(mockctx, &vcwallet.Config{})
	require.NotNil(t, vcwalletCommand)

	vdrCommand, err := vdr.New(mockctx)
	require.NotNil(t, vdrCommand)
	require.NoError(t, err)

	// Command instance
	command, err := New(vdrCommand, vcwalletCommand)
	require.NoError(t, err)

	token, lock1 := command.unlockWallet(t, command.walletuid, command.walletpass)
	defer lock1()

	var b bytes.Buffer

	addCreateKey, err := getReader(&vcwallet.CreateKeyPairRequest{
		WalletAuth: vcwallet.WalletAuth{UserID: command.walletuid, Auth: token},
		KeyType:    kms.ED25519Type,
	})
	require.NoError(t, err)

	err = command.vcwalletcommand.CreateKeyPair(&b, addCreateKey)
	require.NoError(t, err)

	var keyPairResponse vcwallet.CreateKeyPairResponse
	require.NoError(t, json.NewDecoder(&b).Decode(&keyPairResponse))

	pubKey, err := base64.RawURLEncoding.DecodeString(keyPairResponse.PublicKey)
	require.NoError(t, err)

	_, didKID := fingerprint.CreateDIDKeyByCode(fingerprint.ED25519PubKeyMultiCodec, pubKey)
	parts := strings.Split(didKID, "#")
	currentDID := parts[0]
	currentKeyID := parts[1]

	b.Reset()

	command.currentDID = currentDID
	command.currentKeyPair = keyPairResponse
	command.currentKeyPair.KeyID = currentKeyID

	// Success: JWT successfully signed and verified
	t.Run("test Sign and Verify JWT - success", func(t *testing.T) {
		// Sign JWT
		signedJWT := command.signJWT(token)
		require.NotEmpty(t, signedJWT)

		// Verify JWT
		isVerified := command.verifyJWT(token, signedJWT)
		require.NotNil(t, isVerified)
		require.True(t, isVerified)
		fmt.Println("JWT verified")
	})

	// Error case: invalid token
	t.Run("test Sign JWT - invalid token", func(t *testing.T) {
		invalidToken := "invalidToken"
		signedJWT := command.signJWT(invalidToken)

		require.Empty(t, signedJWT, "JWT should be empty for invalid token")
	})

	// Error case: verification failure
	t.Run("test Verify JWT - verification failure", func(t *testing.T) {
		invalidJWT := "invalidJWT"
		isVerified := command.verifyJWT(token, invalidJWT)

		require.False(t, isVerified)
	})

	// Error case: tampered JWT
	t.Run("test Verify JWT - tampered JWT", func(t *testing.T) {
		// Sign with a valid token
		signedJWT := command.signJWT(token)
		require.NotEmpty(t, signedJWT)

		// Create an incorrect (manipulated) JWT
		tamperedJWT := signedJWT + "tamper"

		isVerified := command.verifyJWT(token, tamperedJWT)
		require.False(t, isVerified, "JWT verification should fail for tampered JWT")
	})

}

func TestDoDeviceEnrolment(t *testing.T) {
	t.Run("test DoDeviceEnrolment method - success", func(t *testing.T) {
		const (
			sampleUser1 = "sampleUser1"
			samplePass  = "fakepassphrase"
			sampleDID   = "did:example:123"
			sampleURL   = "https://issuer:9082"
		)

		// Argumentos de prueba para DoDeviceEnrolment
		enrolmentArgs := DoDeviceEnrolmentArgs{
			Url: sampleURL,
			IdProofs: []IdProof{
				{AttrName: "holderName", AttrValue: "FluidosNode"},
				{AttrName: "fluidosRole", AttrValue: "Customer"},
				{AttrName: "deviceType", AttrValue: "Server"},
				{AttrName: "orgIdentifier", AttrValue: "FLUIDOS_id_23241231412"},
				{AttrName: "physicalAddress", AttrValue: "50:80:61:82:ab:c9"},
			},
		}

		mockServer := setupMockEnrolmentServer(t)
		defer mockServer.Close()
		enrolmentArgs.Url = mockServer.URL

		// Serializar el request para simular entrada válida
		var requestBody bytes.Buffer
		err := json.NewEncoder(&requestBody).Encode(enrolmentArgs)
		require.NoError(t, err)

		// Crear mocks
		vcwalletCommand := vcwallet.New(newMockProvider(t), &vcwallet.Config{})
		require.NotNil(t, vcwalletCommand)
		require.NoError(t, err)

		vdrCommand, err := vdr.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      &mockvdr.MockVDRegistry{}, // Mock de VDRegistry
		})
		require.NoError(t, err)

		// Crear nueva instancia de Command
		command, err := New(vdrCommand, vcwalletCommand)
		require.NoError(t, err)

		// Crear writer para capturar la salida
		var l bytes.Buffer

		// Ejecutar DoDeviceEnrolment
		err = command.DoDeviceEnrolment(&l, &requestBody)
		require.NoError(t, err)

		// Validar la respuesta decodificada
		var response DoDeviceEnrolmentResult
		err = json.NewDecoder(&l).Decode(&response)
		require.NoError(t, err)
		require.NotNil(t, response)

		// Imprimir la credencial obtenida
		fmt.Println("Credential storage ID:", response.CredStorageId)
		fmt.Println("Credential:", string(response.Credential))

		var cred map[string]interface{}

		// Decodificar contenido de la credencial
		err = json.Unmarshal(response.Credential, &cred)
		require.NoError(t, err)

		// Mostrar el resultado en formato legible
		prettyCred, err := json.MarshalIndent(cred, "", "  ")
		require.NoError(t, err)

		fmt.Printf("Formatted Credential: %s\n", string(prettyCred))

		fmt.Println()
	})
}

func TestGetVCredential(t *testing.T) {

	// Mocks (vcwallet and vdr)
	vcwalletCommand := vcwallet.New(newMockProvider(t), &vcwallet.Config{})
	require.NotNil(t, vcwalletCommand)

	vdrCommand, err := vdr.New(&mockprovider.Provider{
		StorageProviderValue: mockstore.NewMockStoreProvider(),
		VDRegistryValue:      &mockvdr.MockVDRegistry{}, // Mock VDRegistry
	})
	require.NotNil(t, vdrCommand)
	require.NoError(t, err)

	// New command instance
	command, err := New(vdrCommand, vcwalletCommand)
	require.NoError(t, err)

	// Success: VCredential successfully obtained
	t.Run("test GetVCredential method - success", func(t *testing.T) {
		fmt.Printf("ID of the sought credential: %s\n", sampleCredId)

		// Define valid argument for GetVCredential
		getVCredentialArgs := GetVCredentialArgs{CredId: sampleCredId}
		var l bytes.Buffer
		reader, err := getReader(getVCredentialArgs)
		require.NotNil(t, reader)
		require.NoError(t, err)

		// Sample VC
		vc2 := map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"id":       "http://example.edu/credentials/1872",
			"type":     []string{"VerifiableCredential"},
			"issuer":   map[string]interface{}{"id": "did:example:123"},
			"credentialSubject": map[string]interface{}{
				"id":   "did:example:456",
				"name": "John Doe",
			},
		}

		token1, lock1 := command.unlockWallet(t, command.walletuid, command.walletpass)

		// Add credential to wallet
		err = command.AddCredentialToWallet(command.walletuid, token1, wallet.Credential, vc2, "")
		require.NoError(t, err)

		lock1()

		// GetVCredential method
		err = command.GetVCredential(&l, reader)
		require.NoError(t, err)

		require.NotNil(t, command)

		var response GetVCredentialResult
		err = json.NewDecoder(&l).Decode(&response)
		require.NoError(t, err)

		require.NotNil(t, response)
		// Print result
		fmt.Println(response)

		var didDoc map[string]interface{}

		// Decode DIDDoc content
		err = json.Unmarshal(response.Credential, &didDoc)
		require.NoError(t, err)

		prettyDidDoc, err := json.MarshalIndent(didDoc, "", "  ")
		require.NoError(t, err)

		fmt.Printf("Credential: %s\n", string(prettyDidDoc))

		fmt.Println()
	})

	// Error case: malformed JSON request
	t.Run("test GetVCredential - malformed JSON request", func(t *testing.T) {
		malformedJSON := strings.NewReader("{CredId:}")

		var l bytes.Buffer
		err := command.GetVCredential(&l, malformedJSON)

		require.Error(t, err)
		require.Contains(t, err.Error(), "request decode")
	})

	// Error case: credential not found
	t.Run("test GetVCredential - credential not found", func(t *testing.T) {
		missingCredId := "http://example.edu/credentials/9999"
		getVCredentialArgs := GetVCredentialArgs{CredId: missingCredId}
		reader, err := getReader(getVCredentialArgs)
		require.NoError(t, err)

		var l bytes.Buffer
		err = command.GetVCredential(&l, reader)

		require.Error(t, err)
		require.Contains(t, err.Error(), "data not found")
	})

	// Error case: invalid wallet credentials
	t.Run("test GetVCredential - invalid wallet credentials", func(t *testing.T) {
		command.walletuid = "invalidUserID"
		command.walletpass = "invalidPassphrase"

		var l bytes.Buffer
		getVCredentialArgs := GetVCredentialArgs{CredId: sampleCredId}
		reader, err := getReader(getVCredentialArgs)
		require.NotNil(t, reader)
		require.NoError(t, err)
		err = command.GetVCredential(&l, reader)

		require.Error(t, err)
		require.Contains(t, err.Error(), "profile does not exist")
	})

}

func TestGenerateVP(t *testing.T) {

	// Simulated provider
	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = getMockDIDKeyVDR()

	vcwalletCommand := vcwallet.New(mockctx, &vcwallet.Config{})
	require.NotNil(t, vcwalletCommand)

	vdrCommand, err := vdr.New(mockctx)
	require.NotNil(t, vdrCommand)
	require.NoError(t, err)

	// Command instance
	command, err := New(vdrCommand, vcwalletCommand)
	require.NoError(t, err)

	token1, lock1 := command.unlockWallet(t, command.walletuid, command.walletpass)

	// Add sample credential to wallet
	var sampleNewUDCVc map[string]interface{}
	err = json.Unmarshal(testdata.SampleUDCVC, &sampleNewUDCVc)
	require.NoError(t, err)

	sampleNewUDCVc["id"] = "http://example.edu/credentials/18722"

	// Add credential to wallet
	err = command.AddCredentialToWallet(command.walletuid, token1, wallet.Credential, sampleNewUDCVc, "")
	require.NoError(t, err)

	// sampleUDCVCWithProofBBS includes a proof object, which is essential for credential
	// verification. This provides information that allows systems to validate that the
	// credential has not been tampered with and that it comes from a legitimate source.
	var sampleNewUDCVProofBBS map[string]interface{}
	err = json.Unmarshal(testdata.SampleUDCVCWithProofBBS, &sampleNewUDCVProofBBS)
	require.NoError(t, err)

	err = command.AddCredentialToWallet(command.walletuid, token1, wallet.Credential, sampleNewUDCVProofBBS, "")
	require.NoError(t, err)

	lock1()

	var queryByFrame QueryByFrame
	err = json.Unmarshal(testdata.SampleWalletQueryByFrame, &queryByFrame)
	require.NoError(t, err)

	// Success: VP successfully generated
	t.Run("test Generate VP - success", func(t *testing.T) {
		request := &GenerateVPArgs{
			CredId:       "http://example.edu/credentials/18722",
			QueryByFrame: queryByFrame,
		}
		reqBody, err := json.Marshal(request)
		require.NoError(t, err)

		var b bytes.Buffer
		cmdErr := command.GenerateVP(&b, bytes.NewReader(reqBody))
		require.NoError(t, cmdErr)

		var response GenerateVPResultCustom
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Results)

		t.Log("Prueba de generación de VP exitosa con resultado:", response.Results)
	})

	// Error case: non-existent credential ID
	t.Run("test GenerateVP - non-existent credential ID", func(t *testing.T) {
		request := &GenerateVPArgs{
			CredId:       "http://example.edu/credentials/unknownID",
			QueryByFrame: queryByFrame,
		}

		reqBody, err := json.Marshal(request)
		require.NoError(t, err)

		var b bytes.Buffer
		cmdErr := command.GenerateVP(&b, bytes.NewReader(reqBody))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "data not found")
	})

	// Error case: empty QueryByFrame
	t.Run("test GenerateVP - empty QueryByFrame", func(t *testing.T) {
		request := &GenerateVPArgs{
			CredId:       "http://example.edu/credentials/18722",
			QueryByFrame: QueryByFrame{},
		}

		reqBody, err := json.Marshal(request)
		require.NoError(t, err)

		var b bytes.Buffer
		cmdErr := command.GenerateVP(&b, bytes.NewReader(reqBody))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "query response not working")
	})

	// Error case: missing CredId in request
	t.Run("test GenerateVP - missing CredId in request", func(t *testing.T) {
		request := &GenerateVPArgs{
			CredId:       "",
			QueryByFrame: queryByFrame,
		}

		reqBody, err := json.Marshal(request)
		require.NoError(t, err)

		var b bytes.Buffer
		cmdErr := command.GenerateVP(&b, bytes.NewReader(reqBody))

		require.Error(t, cmdErr)
		require.Contains(t, cmdErr.Error(), "data not found")
	})

}

func TestVerifyCredential(t *testing.T) {
	const (
		sampleUser1    = "sampleUser1"
		fakePassphrase = "fakepassphrase"
	)

	// Simulated provider
	mockctx := newMockProvider(t)
	mockctx.VDRegistryValue = getMockDIDKeyVDR()

	vcwalletCommand := vcwallet.New(mockctx, &vcwallet.Config{})
	require.NotNil(t, vcwalletCommand)

	vdrCommand, err := vdr.New(mockctx)
	require.NotNil(t, vdrCommand)
	require.NoError(t, err)

	// Command instance
	command, err := New(vdrCommand, vcwalletCommand)
	require.NoError(t, err)

	// Create sample profile
	err = command.createSampleUserProfile(t, sampleUser1, fakePassphrase)
	require.NoError(t, err)

	token1, lock1 := command.unlockWallet(t, sampleUser1, fakePassphrase)
	defer lock1()

	// Add sample credential to wallet
	var sampleNewUDCVc map[string]interface{}
	err = json.Unmarshal(testdata.SampleUDCVC, &sampleNewUDCVc)
	require.NoError(t, err)

	sampleNewUDCVc["id"] = "http://example.edu/credentials/18722"

	// Add credential to wallet
	err = command.AddCredentialToWallet(sampleUser1, token1, wallet.Credential, sampleNewUDCVc, "")
	require.NoError(t, err)

	// sampleUDCVCWithProofBBS includes a proof object, which is essential for credential
	// verification. This provides information that allows systems to validate that the
	// credential has not been tampered with and that it comes from a legitimate source.
	var sampleNewUDCVProofBBS map[string]interface{}
	err = json.Unmarshal(testdata.SampleUDCVCWithProofBBS, &sampleNewUDCVProofBBS)
	require.NoError(t, err)

	err = command.AddCredentialToWallet(sampleUser1, token1, wallet.Credential, sampleNewUDCVProofBBS, "")
	require.NoError(t, err)

	t.Run("successfully issue VP and verify it", func(t *testing.T) {
		// Part I: Issue VP
		var queryByFrame QueryByFrame
		err := json.Unmarshal(testdata.SampleWalletQueryByFrame, &queryByFrame)
		require.NoError(t, err)

		request := &GenerateVPArgs{
			CredId:       "http://example.edu/credentials/18722",
			QueryByFrame: queryByFrame,
		}

		reqBody, err := json.Marshal(request)
		require.NoError(t, err)

		var b bytes.Buffer
		cmdErr := command.GenerateVP(&b, bytes.NewReader(reqBody))
		require.NoError(t, cmdErr)

		var res GenerateVPResultCustom
		require.NoError(t, json.NewDecoder(&b).Decode(&res))
		require.NotEmpty(t, res)
		require.NotEmpty(t, res.Results)

		var l bytes.Buffer
		reader, err := getReader(VerifyCredentialArgs{CredentialString: string(*res.Results[0])})
		require.NotNil(t, reader)
		require.NoError(t, err)

		// Part II: call VerifyCredential method
		err = command.VerifyCredential(&l, reader)
		require.NoError(t, err)

		// Validate response
		var response VerifyCredentialResult
		err = json.NewDecoder(&l).Decode(&response)
		require.NoError(t, err)

		// Assert result
		require.True(t, response.Result)
		// Print result
		fmt.Printf("Credential verification result: %v\n", response.Result)
	})
}

/**
func TestAcceptEnrolment(t *testing.T) {
	t.Run("test AcceptEnrolment method - success", func(t *testing.T) {
		const (
			sampleUser     = "sampleUser1"
			fakePassphrase = "fakepassphrase"
			sampleDID      = "did:peer:21tDAKCERh95uGgKbJNHYp"
		)

		// idProofs definition
		idProofs := []IdProof{
			{AttrName: "holderName", AttrValue: "FluidosNode"},
			{AttrName: "fluidosRole", AttrValue: "Customer"},
			{AttrName: "deviceType", AttrValue: "Server"},
			{AttrName: "orgIdentifier", AttrValue: "FLUIDOS_id_23241231412"},
			{AttrName: "DID", AttrValue: sampleDID},
		}

		// AcceptEnrolment arguments
		acceptEnrolmentArgs := AcceptEnrolmentArgs{IdProofs: idProofs}

		var l bytes.Buffer
		reader, err := getReader(acceptEnrolmentArgs)
		require.NotNil(t, reader)
		require.NoError(t, err)

		// Simulated provider
		mockctx := newMockProvider(t)
		mockctx.VDRegistryValue = getMockDIDKeyVDR()

		vcwalletCommand := vcwallet.New(mockctx, &vcwallet.Config{})
		require.NotNil(t, vcwalletCommand)

		vdrCommand, err := vdr.New(mockctx)
		require.NotNil(t, vdrCommand)
		require.NoError(t, err)

		// Command instance
		command, err := New(vdrCommand, vcwalletCommand)
		require.NoError(t, err)

		// Create sample profile
		err = command.createSampleUserProfile(t, sampleUser, fakePassphrase)
		require.NoError(t, err)

		token, lock := command.unlockWallet(t, sampleUser, fakePassphrase)
		defer lock()

		// Agregar credencial a la billetera
		baseCred := map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"id":       "http://example.edu/credentials/123",
			"type":     []string{"VerifiableCredential"},
			"issuer": map[string]interface{}{
				"id": "did:peer:21tDAKCERh95uGgKbJNHYp",
			},
			"issuanceDate": "2024-10-23T00:00:00Z",
			"credentialSubject": map[string]interface{}{
				"id":     "did:peer:21tDAKCERh95uGgKbJNHYp",
				"name":   "John Doe",
				"degree": "Bachelor of Science",
				"year":   2024,
			},
		}

		// Define currentDID
		command.currentDID = sampleDID

		// Add DID To VDR
		command.AddDIDToVDR(t)

		// Asegúrate de que el método que usas para agregar a la billetera espera datos en el formato correcto
		err = command.AddCredentialToWallet(sampleUser, token, wallet.Credential, baseCred, "")
		require.NoError(t, err)

		// Llamar al método AcceptEnrolment
		err = command.AcceptEnrolment(&l, reader)
		require.NoError(t, err)

		// Verificar el resultado
		var response AcceptEnrolmentResult
		err = json.NewDecoder(&l).Decode(&response)
		require.NoError(t, err)

		require.NotNil(t, response)

		// Imprimir el resultado de la credencial emitida
		var didDoc map[string]interface{}
		err = json.Unmarshal(response.Credential, &didDoc)
		require.NoError(t, err)

		prettyDidDoc, err := json.MarshalIndent(didDoc, "", "  ")
		require.NoError(t, err)

		fmt.Printf("Credential: %s\n", string(prettyDidDoc))

		fmt.Println("AcceptEnrolment executed successfully.")
	})
}
**/

func readDIDtesting(t *testing.T) {

}

func newMockProvider(t *testing.T) *mockprovider.Provider {
	t.Helper()

	loader, err := ldtestutil.DocumentLoader()
	require.NoError(t, err)

	serviceMap := map[string]interface{}{
		presentproofSvc.Name:    &mockpresentproof.MockPresentProofSvc{},
		outofbandSvc.Name:       &mockoutofband.MockOobService{},
		didexchange.DIDExchange: &mockdidexchange.MockDIDExchangeSvc{},
		mediator.Coordination:   &mockmediator.MockMediatorSvc{},
		issuecredentialsvc.Name: &mockissuecredential.MockIssueCredentialSvc{},
		oobv2.Name:              &mockoutofbandv2.MockOobService{},
	}

	return &mockprovider.Provider{
		StorageProviderValue:              mockstore.NewMockStoreProvider(),
		ProtocolStateStorageProviderValue: mockstore.NewMockStoreProvider(),
		DocumentLoaderValue:               loader,
		ServiceMap:                        serviceMap,
	}
}

func (o *Command) unlockWallet(t *testing.T, sampleUser string, localKMS string) (string, func()) {
	var b bytes.Buffer

	openReader, err := getReader(&vcwallet.UnlockWalletRequest{
		UserID:             sampleUser,
		LocalKMSPassphrase: localKMS,
	})
	require.NoError(t, err)

	cmdErr := o.vcwalletcommand.Open(&b, openReader)
	require.NoError(t, cmdErr)

	lockReader, err := getReader(&vcwallet.LockWalletRequest{
		UserID: sampleUser,
	})
	require.NoError(t, err)

	return getUnlockToken(b), func() {
		cmdErr = o.vcwalletcommand.Close(&b, lockReader)
		if cmdErr != nil {
			t.Log(t, cmdErr)
		}
	}
}

func (o *Command) createSampleUserProfile(t *testing.T, sampleUser string, localKMS string) error {
	var l bytes.Buffer

	createReader, err := getReader(&vcwallet.CreateOrUpdateProfileRequest{
		UserID:             sampleUser,
		LocalKMSPassphrase: localKMS,
	})
	require.NoError(t, err)

	cmdErr := o.vcwalletcommand.CreateProfile(&l, createReader)
	require.NoError(t, cmdErr)

	return nil
}

func (o *Command) AddCredentialToWallet(userID string, walletAuth string, contentType wallet.ContentType, content interface{}, collectionID string) error {

	rawContent, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("error al convertir el contenido a json.RawMessage: %w", err)
	}

	// Añadir el contenido al wallet
	addReader, err := getReader(&vcwallet.AddContentRequest{
		WalletAuth: vcwallet.WalletAuth{
			UserID: userID,
			Auth:   walletAuth,
		},
		ContentType:  contentType,
		Content:      rawContent,
		CollectionID: collectionID,
	})
	if err != nil {
		return fmt.Errorf("error al preparar la solicitud de adición de contenido: %w", err)
	}

	var addResponse bytes.Buffer
	err = o.vcwalletcommand.Add(&addResponse, addReader)
	if err != nil {
		return fmt.Errorf("error al añadir el contenido al wallet: %w", err)
	}

	return nil
}

func (o *Command) AddDIDToVDR(t *testing.T) error {
	doc := map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/did/v2",
		},
		"id": "did:peer:21tDAKCERh95uGgKbJNHYp",
		"verificationMethod": []map[string]interface{}{
			{
				"id":              "did:peer:123456789abcdefghi#keys-1",
				"type":            "Secp256k1VerificationKey2018",
				"controller":      "did:peer:123456789abcdefghi",
				"publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
			},
			{
				"id":         "did:peer:123456789abcdefghw#key2",
				"type":       "RsaVerificationKey2018",
				"controller": "did:peer:123456789abcdefghw",
				"publicKeyPem": `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryQICCl6NZ5gDKrnSztO
3Hy8PEUcuyvg/ikC+VcIo2SFFSf18a3IMYldIugqqqZCs4/4uVW3sbdLs/6PfgdX
7O9D22ZiFWHPYA2k2N744MNiCD1UE+tJyllUhSblK48bn+v1oZHCM0nYQ2NqUkvS
j+hwUU3RiWl7x3D2s9wSdNt7XUtW05a/FXehsPSiJfKvHJJnGOX0BgTvkLnkAOTd
OrUZ/wK69Dzu4IvrN4vs9Nes8vbwPa/ddZEzGR0cQMt0JBkhk9kU/qwqUseP1QRJ
5I1jR4g8aYPL/ke9K35PxZWuDp3U0UPAZ3PjFAh+5T+fc7gzCs9dPzSHloruU+gl
FQIDAQAB
-----END PUBLIC KEY-----`,
			},
		},
	}

	rawContent, err := json.Marshal(doc)
	require.NoError(t, err)

	createDIDReq := &vdr.DIDArgs{
		Document: vdr.Document{DID: rawContent},
		Name:     sampleDIDName,
	}
	reqBytes, err := json.Marshal(createDIDReq)
	require.NoError(t, err)

	var getRW bytes.Buffer
	cmdErr := o.vdrcommand.SaveDID(&getRW, bytes.NewBuffer(reqBytes))
	require.NoError(t, cmdErr)

	return nil
}

func getMockDIDKeyVDR() *mockvdr.MockVDRegistry {
	return &mockvdr.MockVDRegistry{
		ResolveFunc: func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
			if strings.HasPrefix(didID, "did:key:") {
				k := key.New()

				d, e := k.Read(didID)
				if e != nil {
					return nil, e
				}

				return d, nil
			}

			return nil, fmt.Errorf("did not found")
		},
	}
}

// Posible problema: o.currentDID no definido
// Añadir a este método la funcionalidad de comprobación de solicitud
func setupMockEnrolmentServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Asegurar que la URL es la esperada
		assert.Equal(t, "/fluidos/idm/acceptEnrolment", req.URL.Path)

		issuanceDate := time.Now().Format(time.RFC3339Nano)
		expirationDate := time.Now().AddDate(0, 0, 1).Format(time.RFC3339Nano) // Añadir un día para la fecha de expiración

		// Simulate the enrollment response
		response := map[string]interface{}{
			"credential": map[string]interface{}{
				"@context": []string{
					"https://www.w3.org/2018/credentials/v1",
					"https://www.w3.org/2018/credentials/examples/v1",
					"https://ssiproject.inf.um.es/security/psms/v1",
					"https://ssiproject.inf.um.es/poc/context/v1",
				},
				"credentialSubject": map[string]interface{}{
					"DID":             "did:fabric:DuYKXxLuWnTQzBaa9p1eT1Aya98nirASjVN8dphJjYw",
					"deviceType":      "Server",
					"fluidosRole":     "Customer",
					"holderName":      "FluidosNode",
					"orgIdentifier":   "FLUIDOS_id_23241231412",
					"physicalAddress": "50:80:61:82:ab:c9",
				},
				"expirationDate": expirationDate,
				"id":             "did:fabric:IDDOde0vxswhzfNEQwp05_B209NZ8Ssf3IHHhlrt7Ho3068409",
				"issuanceDate":   issuanceDate,
				"issuer":         "did:fabric:IDDOde0vxswhzfNEQwp05_B209NZ8Ssf3IHHhlrt7Ho",
				"proof": map[string]interface{}{
					"created":            issuanceDate,
					"proofPurpose":       "assertionMethod",
					"proofValue":         "BBVHMPF6Alk2zs934vLFUMg6p83X6TsHI1sE_FJ6GX2AHaFDaXuqZ8PZuQHeRRUKYBIXd2TfGmUvZkec77bXhtEL_yo2wtHiX8vMWUDWQ_fzZ4Y6QG9FYJM2wzaexf43xRiyvYWxiONADhz3sNQHILrHgrSVP1fLyGMIocrrQaGs3xf0-ydEUdfCkpsQNZcFmwMuHh_oUC3MJ5RdkkImP6HIruU-Ke7fM4VYcfnd-Pq7FvwfmSDF33Xbn3Zs0vfp2AQY2WKP1X8IcEuLMea6_0YPHhNRdNn-PA-cUqZXPCDQ2uL40Kud6AdCn7Nms3G5ztUKPD50CXzch8PbyPdVw_mjZYpWEd2xwxc4JIjXeXGPKJo8fjxeQHf5aVyn1HCCg7IIo1UMt-M921Z-hllYZuMrGIOTINKYhPjxBKSXwWw4UTt55k0xzZcrtTM8oFCk0j8Vo8mhjM7albUekUfoQwMaw9xvo9pdYIM9v55B2ooQ8ivVCzNSWoAJIj_YrnyMCfeE0vcYnnYUE_j69Whok_c2FuRODPv1TFnICWk6FGC5bhfxF-xMVT4Pt6uyfWn86os",
					"type":               "PsmsBlsSignature2022",
					"verificationMethod": "did:fabric:IDDOde0vxswhzfNEQwp05_B209NZ8Ssf3IHHhlrt7Ho#xcrh0rw2Gxlx-SZRQQhi5h4YJ9_VEv_hV9X7sV2unlI",
				},
				"type": []string{
					"VerifiableCredential",
					"FluidosCredential",
				},
			},
			"credStorageId": "did:fabric:IDDOde0vxswhzfNEQwp05_B209NZ8Ssf3IHHhlrt7Ho3068409",
		}

		rw.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(rw).Encode(response)
		require.NoError(t, err)
	}))
}
