package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/payment-system/dq-vault/api/helpers"
	"github.com/payment-system/dq-vault/config"
)

// Test constants for register tests
const (
	regTestUsername        = "test-user"
	regTestValidMnemonic   = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	regTestInvalidMnemonic = "invalid mnemonic words that do not form valid bip39"
	regTestPassphrase      = "test-passphrase"
	regTestGeneratedUUID   = "generated-uuid-123"
)

// MockStorageRegister implements logical.Storage for testing
type MockStorageRegister struct {
	mock.Mock
}

func (m *MockStorageRegister) List(ctx context.Context, prefix string) ([]string, error) {
	args := m.Called(ctx, prefix)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorageRegister) Get(ctx context.Context, key string) (*logical.StorageEntry, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*logical.StorageEntry), args.Error(1)
}

func (m *MockStorageRegister) Put(ctx context.Context, entry *logical.StorageEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *MockStorageRegister) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

// Helper function to create a proper framework.FieldData for register endpoint
func createRegisterFieldData(data map[string]interface{}) *framework.FieldData {
	schema := map[string]*framework.FieldSchema{
		"uuid": {
			Type:        framework.TypeString,
			Description: "UUID of user (required)",
			Required:    true,
		},
		"username": {
			Type:        framework.TypeString,
			Description: "Username for registration",
		},
		"mnemonic": {
			Type:        framework.TypeString,
			Description: "BIP39 mnemonic phrase",
		},
		"passphrase": {
			Type:        framework.TypeString,
			Description: "Passphrase for mnemonic",
		},
	}

	return &framework.FieldData{
		Raw:    data,
		Schema: schema,
	}
}

// Helper function to create field data for register_uuid endpoint (no UUID)
func createRegisterAutoFieldData(data map[string]interface{}) *framework.FieldData {
	schema := map[string]*framework.FieldSchema{
		"username": {
			Type:        framework.TypeString,
			Description: "Username for registration",
		},
		"mnemonic": {
			Type:        framework.TypeString,
			Description: "BIP39 mnemonic phrase",
		},
		"passphrase": {
			Type:        framework.TypeString,
			Description: "Passphrase for mnemonic",
		},
	}

	return &framework.FieldData{
		Raw:    data,
		Schema: schema,
	}
}

// Helper function to create test backend for register tests
func createRegisterTestBackend(_ *testing.T) *Backend {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	return &Backend{
		logger: logger,
	}
}

// TestBackend_PathRegister tests the /register endpoint (requires UUID)
func TestBackend_PathRegister(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		fieldData      map[string]interface{}
		setupStorage   func(*MockStorageRegister)
		want           *logical.Response
		wantErr        bool
		wantStatusCode int
		wantErrMsg     string
	}{
		{
			name: "successful registration with provided mnemonic and UUID",
			fieldData: map[string]interface{}{
				"uuid":       regTestGeneratedUUID,
				"username":   regTestUsername,
				"mnemonic":   regTestValidMnemonic,
				"passphrase": regTestPassphrase,
			},
			setupStorage: func(ms *MockStorageRegister) {
				ms.On("List", ctx, config.StorageBasePath).Return([]string{}, nil)
				ms.On("Put", ctx, mock.AnythingOfType("*logical.StorageEntry")).Return(nil)
			},
			want: &logical.Response{
				Data: map[string]interface{}{
					"uuid": regTestGeneratedUUID,
				},
			},
			wantErr: false,
		},
		{
			name: "successful registration with empty mnemonic (auto-generated)",
			fieldData: map[string]interface{}{
				"uuid":       regTestGeneratedUUID,
				"username":   regTestUsername,
				"mnemonic":   "",
				"passphrase": regTestPassphrase,
			},
			setupStorage: func(ms *MockStorageRegister) {
				ms.On("List", ctx, config.StorageBasePath).Return([]string{}, nil)
				ms.On("Put", ctx, mock.AnythingOfType("*logical.StorageEntry")).Return(nil)
			},
			want: &logical.Response{
				Data: map[string]interface{}{
					"uuid": regTestGeneratedUUID,
				},
			},
			wantErr: false,
		},
		{
			name: "missing UUID field",
			fieldData: map[string]interface{}{
				"username":   regTestUsername,
				"mnemonic":   regTestValidMnemonic,
				"passphrase": regTestPassphrase,
			},
			setupStorage:   func(_ *MockStorageRegister) {},
			wantErr:        true,
			wantStatusCode: http.StatusUnprocessableEntity,
			wantErrMsg:     "UUID is required",
		},
		{
			name: "empty UUID",
			fieldData: map[string]interface{}{
				"uuid":       "",
				"username":   regTestUsername,
				"mnemonic":   regTestValidMnemonic,
				"passphrase": regTestPassphrase,
			},
			setupStorage:   func(_ *MockStorageRegister) {},
			wantErr:        true,
			wantStatusCode: http.StatusUnprocessableEntity,
			wantErrMsg:     "UUID is required",
		},
		{
			name: "UUID already exists",
			fieldData: map[string]interface{}{
				"uuid":       regTestGeneratedUUID,
				"username":   regTestUsername,
				"mnemonic":   regTestValidMnemonic,
				"passphrase": regTestPassphrase,
			},
			setupStorage: func(ms *MockStorageRegister) {
				ms.On("List", ctx, config.StorageBasePath).Return([]string{regTestGeneratedUUID}, nil)
			},
			wantErr:        true,
			wantStatusCode: http.StatusUnprocessableEntity,
			wantErrMsg:     "UUID already exists",
		},
		{
			name: "invalid mnemonic provided",
			fieldData: map[string]interface{}{
				"uuid":       regTestGeneratedUUID,
				"username":   regTestUsername,
				"mnemonic":   regTestInvalidMnemonic,
				"passphrase": regTestPassphrase,
			},
			setupStorage: func(ms *MockStorageRegister) {
				ms.On("List", ctx, config.StorageBasePath).Return([]string{}, nil)
			},
			wantErr:        true,
			wantStatusCode: http.StatusExpectationFailed,
			wantErrMsg:     "Invalid Mnemonic",
		},
		{
			name: "storage put error",
			fieldData: map[string]interface{}{
				"uuid":       regTestGeneratedUUID,
				"username":   regTestUsername,
				"mnemonic":   regTestValidMnemonic,
				"passphrase": regTestPassphrase,
			},
			setupStorage: func(ms *MockStorageRegister) {
				ms.On("List", ctx, config.StorageBasePath).Return([]string{}, nil)
				ms.On("Put", ctx, mock.AnythingOfType("*logical.StorageEntry")).Return(assert.AnError)
			},
			wantErr:        true,
			wantStatusCode: http.StatusExpectationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := new(MockStorageRegister)
			backend := createRegisterTestBackend(t)

			if tt.setupStorage != nil {
				tt.setupStorage(mockStorage)
			}

			fieldData := createRegisterFieldData(tt.fieldData)
			req := &logical.Request{
				Storage: mockStorage,
				Data:    tt.fieldData,
			}

			got, err := backend.pathRegister(ctx, req, fieldData)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantStatusCode != 0 {
					if codedErr, ok := err.(logical.HTTPCodedError); ok {
						assert.Equal(t, tt.wantStatusCode, codedErr.Code())
					}
				}
				if tt.wantErrMsg != "" {
					assert.Contains(t, err.Error(), tt.wantErrMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				if tt.want != nil {
					assert.Equal(t, tt.want.Data["uuid"], got.Data["uuid"])
				}
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

// TestBackend_PathRegisterUUID tests the /register_uuid endpoint (auto-generates UUID)
func TestBackend_PathRegisterUUID(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		fieldData      map[string]interface{}
		setupStorage   func(*MockStorageRegister)
		wantErr        bool
		wantStatusCode int
		wantErrMsg     string
	}{
		{
			name: "successful registration with auto-generated UUID",
			fieldData: map[string]interface{}{
				"username":   regTestUsername,
				"mnemonic":   regTestValidMnemonic,
				"passphrase": regTestPassphrase,
			},
			setupStorage: func(ms *MockStorageRegister) {
				ms.On("List", ctx, config.StorageBasePath).Return([]string{}, nil)
				ms.On("Put", ctx, mock.AnythingOfType("*logical.StorageEntry")).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "successful registration with empty mnemonic (auto-generated)",
			fieldData: map[string]interface{}{
				"username":   regTestUsername,
				"mnemonic":   "",
				"passphrase": regTestPassphrase,
			},
			setupStorage: func(ms *MockStorageRegister) {
				ms.On("List", ctx, config.StorageBasePath).Return([]string{}, nil)
				ms.On("Put", ctx, mock.AnythingOfType("*logical.StorageEntry")).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "successful registration with no passphrase",
			fieldData: map[string]interface{}{
				"username": regTestUsername,
				"mnemonic": regTestValidMnemonic,
			},
			setupStorage: func(ms *MockStorageRegister) {
				ms.On("List", ctx, config.StorageBasePath).Return([]string{}, nil)
				ms.On("Put", ctx, mock.AnythingOfType("*logical.StorageEntry")).Return(nil)
			},
			wantErr: false,
		},
		{
			name: "invalid mnemonic provided",
			fieldData: map[string]interface{}{
				"username":   regTestUsername,
				"mnemonic":   regTestInvalidMnemonic,
				"passphrase": regTestPassphrase,
			},
			setupStorage: func(ms *MockStorageRegister) {
				ms.On("List", ctx, config.StorageBasePath).Return([]string{}, nil)
			},
			wantErr:        true,
			wantStatusCode: http.StatusExpectationFailed,
			wantErrMsg:     "Invalid Mnemonic",
		},
		{
			name: "storage put error",
			fieldData: map[string]interface{}{
				"username":   regTestUsername,
				"mnemonic":   regTestValidMnemonic,
				"passphrase": regTestPassphrase,
			},
			setupStorage: func(ms *MockStorageRegister) {
				ms.On("List", ctx, config.StorageBasePath).Return([]string{}, nil)
				ms.On("Put", ctx, mock.AnythingOfType("*logical.StorageEntry")).Return(assert.AnError)
			},
			wantErr:        true,
			wantStatusCode: http.StatusExpectationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := new(MockStorageRegister)
			backend := createRegisterTestBackend(t)

			if tt.setupStorage != nil {
				tt.setupStorage(mockStorage)
			}

			fieldData := createRegisterAutoFieldData(tt.fieldData)
			req := &logical.Request{
				Storage: mockStorage,
				Data:    tt.fieldData,
			}

			got, err := backend.pathRegisterUUID(ctx, req, fieldData)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.wantStatusCode != 0 {
					if codedErr, ok := err.(logical.HTTPCodedError); ok {
						assert.Equal(t, tt.wantStatusCode, codedErr.Code())
					}
				}
				if tt.wantErrMsg != "" {
					assert.Contains(t, err.Error(), tt.wantErrMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				// Verify UUID was auto-generated
				assert.Contains(t, got.Data, "uuid")
				uuid, ok := got.Data["uuid"].(string)
				assert.True(t, ok)
				assert.NotEmpty(t, uuid)
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

func TestBackend_PathRegisterUUID_StorageContent(t *testing.T) {
	ctx := context.Background()
	mockStorage := new(MockStorageRegister)
	backend := createRegisterTestBackend(t)

	// Capture the storage entry to verify its content
	var capturedEntry *logical.StorageEntry
	mockStorage.On("List", ctx, config.StorageBasePath).Return([]string{}, nil)
	mockStorage.On("Put", ctx, mock.AnythingOfType("*logical.StorageEntry")).Run(func(args mock.Arguments) {
		capturedEntry = args.Get(1).(*logical.StorageEntry)
	}).Return(nil)

	fieldData := createRegisterAutoFieldData(map[string]interface{}{
		"username":   regTestUsername,
		"mnemonic":   regTestValidMnemonic,
		"passphrase": regTestPassphrase,
	})

	req := &logical.Request{
		Storage: mockStorage,
		Data: map[string]interface{}{
			"username":   regTestUsername,
			"mnemonic":   regTestValidMnemonic,
			"passphrase": regTestPassphrase,
		},
	}

	got, err := backend.pathRegisterUUID(ctx, req, fieldData)

	assert.NoError(t, err)
	assert.NotNil(t, got)

	// Verify storage content
	require.NotNil(t, capturedEntry)

	var storedUser helpers.User
	err = json.Unmarshal(capturedEntry.Value, &storedUser)
	require.NoError(t, err)

	assert.Equal(t, regTestUsername, storedUser.Username)
	assert.Equal(t, regTestValidMnemonic, storedUser.Mnemonic)
	assert.Equal(t, regTestPassphrase, storedUser.Passphrase)
	assert.NotEmpty(t, storedUser.UUID)

	// Verify UUID matches response
	assert.Equal(t, got.Data["uuid"], storedUser.UUID)

	// Verify storage path
	expectedPath := config.StorageBasePath + storedUser.UUID
	assert.Equal(t, expectedPath, capturedEntry.Key)

	mockStorage.AssertExpectations(t)
}
