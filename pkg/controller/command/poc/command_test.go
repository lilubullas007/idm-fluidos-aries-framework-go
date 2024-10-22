/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package poc

import (
	"bytes"
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
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/stretchr/testify/assert"

	"testing"
)

const sampleDIDName = "sampleDIDName"

func TestNewDID(t *testing.T) {
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

		// fmt.Printf("VDR Command: %+v\n", vdrCommand)
		command, err := New(vdrCommand, vcwalletCommand)
		require.NoError(t, err)

		// fmt.Printf("Reader: %+v\n", reader)
		// fmt.Printf("Command: %+v\n", command)
		err = command.NewDID(&l, reader)

		require.NoError(t, err)
		require.NotNil(t, command)

		var response NewDIDResult

		err = json.NewDecoder(&l).Decode(&response)
		require.NoError(t, err)

		fmt.Println(response)

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
	t.Run("test GetVCredential method - success", func(t *testing.T) {
		const (
			sampleUser1    = "sampleUser1"
			sampleCredId   = "http://example.edu/credentials/1872"
			fakePassphrase = "fakepassphrase"
		)

		fmt.Printf("ID of the sought credential: %s\n", sampleCredId)

		// Define valid argument for GetVCredential
		getVCredentialArgs := GetVCredentialArgs{CredId: sampleCredId}
		var l bytes.Buffer
		reader, err := getReader(getVCredentialArgs)
		require.NotNil(t, reader)
		require.NoError(t, err)

		// Mocks (vcwallet and vdr)
		vcwalletCommand := vcwallet.New(newMockProvider(t), &vcwallet.Config{})
		require.NotNil(t, vcwalletCommand)
		require.NoError(t, err)

		vdrCommand, err := vdr.New(&mockprovider.Provider{
			StorageProviderValue: mockstore.NewMockStoreProvider(),
			VDRegistryValue:      &mockvdr.MockVDRegistry{}, // Mock VDRegistry
		})
		require.NotNil(t, vdrCommand)
		require.NoError(t, err)

		// New command instance
		command, err := New(vdrCommand, vcwalletCommand)
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

		// Create sample profile
		err = command.createSampleUserProfile(t, sampleUser1, fakePassphrase)
		require.NoError(t, err)

		token1, lock1 := command.unlockWallet(t, sampleUser1, fakePassphrase)
		defer lock1()

		// Add credential to wallet
		err = command.AddCredentialToWallet(sampleUser1, token1, wallet.Credential, vc2, "")
		require.NoError(t, err)

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
}

func TestGenerateVP(t *testing.T) {
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

	t.Run("successfully create command and generate verifiable presentation", func(t *testing.T) {
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

		var response GenerateVPResultCustom
		require.NoError(t, json.NewDecoder(&b).Decode(&response))
		require.NotEmpty(t, response)
		require.NotEmpty(t, response.Results)

		t.Log("Prueba de generación de VP exitosa con resultado:", response.Results)
	})
}

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

func setupMockEnrolmentServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Asegurar que la URL es la esperada
		assert.Equal(t, "/fluidos/idm/acceptEnrolment", req.URL.Path)

		// Generar las fechas dinámicas
		issuanceDate := time.Now().Format(time.RFC3339Nano)
		expirationDate := time.Now().AddDate(0, 0, 1).Format(time.RFC3339Nano) // Añadir un día para la fecha de expiración

		// Simular la respuesta de enrolamiento
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
