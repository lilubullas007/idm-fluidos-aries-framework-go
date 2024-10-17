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

	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"

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

func TestGetVCredential(t *testing.T) {
	t.Run("test GetVCredential method - success", func(t *testing.T) {
		/**
		// Sample VC
		vc := `{
			"@context": ["https://www.w3.org/2018/credentials/v1"],
			"id": "http://example.edu/credentials/1872",
			"type": ["VerifiableCredential"],
			"issuer": {
				"id": "did:example:123"
			},
			"credentialSubject": {
				"id": "did:example:456",
				"name": "John Doe"
			}
		}`

		// Crear el almacenamiento simulado con la credencial verificable
		storeData := make(map[string]mockstore.DBEntry)
		storeData["sampleCredId"] = mockstore.DBEntry{Value: []byte(vc)}
		**/

		const (
			sampleUser1  = "sampleUser1"
			sampleCredId = "http://example.edu/credentials/1872"
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

		// Create test profile
		err = command.createSampleUserProfile(t, sampleUser1, "fakepassphrase")
		if err != nil {
			logutil.LogInfo(logger, "createProfileCommand", "createProfile", "Error al crear el perfil:", err.Error())
		}

		var token1 string
		var lock1 func()
		token1, lock1 = command.unlockWallet(t, sampleUser1, "fakepassphrase")
		defer lock1()

		// Add credential to wallet
		err = command.AddCredentialToWallet(sampleUser1, token1, wallet.Credential, vc2, "")
		if err != nil {
			logutil.LogInfo(logger, "addToWalletCommand", "addToWallet", "Error al añadir la credencial al wallet:", err.Error())
		}

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
