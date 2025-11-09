package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/payment-system/dq-vault/api/helpers"
	"github.com/payment-system/dq-vault/config"
	"github.com/payment-system/dq-vault/lib"
)

// pathPassphrase corresponds to POST gen/passphrase.
func (b *Backend) pathRegister(ctx context.Context, req *logical.Request,
	d *framework.FieldData) (*logical.Response, error) {
	var err error
	backendLogger := b.logger.With(slog.String("op", "path_register"))
	if err = helpers.ValidateFields(req, d); err != nil {
		backendLogger.Error("validate fields", "error", err)
		return nil, logical.CodedError(http.StatusUnprocessableEntity, err.Error())
	}

	// obatin username
	username := d.Get("username").(string)

	// obtain mnemonic and passphrase of user
	mnemonic := d.Get("mnemonic").(string)
	passphrase := d.Get("passphrase").(string)

	// default entropy length
	entropyLength := config.Entropy

	uuid := d.Get("uuid").(string)
	for helpers.UUIDExists(ctx, req, uuid) {
		return nil, logical.CodedError(http.StatusUnprocessableEntity, "UUID already exists")
	}

	// generated storage path to store user info
	storagePath := config.StorageBasePath + uuid

	if mnemonic == "" {
		// generate new mnemonics if not provided by user
		// obtain mnemonics from entropy
		mnemonic, err = lib.MnemonicFromEntropy(entropyLength)
		if err != nil {
			backendLogger.Error("generate mnemonic", "error", err)
			return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
		}
	}

	// check if mnemonic is valid or not
	if !lib.IsMnemonicValid(mnemonic) {
		backendLogger.Error("invalid mnemonic", "mnemonic", mnemonic)
		return nil, logical.CodedError(http.StatusExpectationFailed, "Invalid Mnemonic")
	}

	// create object to store user information
	user := &helpers.User{
		Username:   username,
		UUID:       uuid,
		Mnemonic:   mnemonic,
		Passphrase: passphrase,
	}

	// creates strorage entry with user JSON encoded value
	store, err := logical.StorageEntryJSON(storagePath, user)
	if err != nil {
		backendLogger.Error("create storage entry", "error", err)
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	// put user information in store
	if err = req.Storage.Put(ctx, store); err != nil {
		backendLogger.Error("put user information", "error", err)
		return nil, logical.CodedError(http.StatusExpectationFailed, err.Error())
	}

	backendLogger.Info("user registered", "username", username)

	return &logical.Response{
		Data: map[string]interface{}{
			"uuid": uuid,
		},
	}, nil
}
