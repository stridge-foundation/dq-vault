package api

import (
	"context"
	"log/slog"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

// Factory creates a new usable instance of this secrets engine.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := NewBackend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, errors.Wrap(err, "failed to create vault factory")
	}
	return b, nil
}

// Backend is the actual backend.
type Backend struct {
	*framework.Backend
	logger *slog.Logger
}

// NewBackend creates a new backend.
func NewBackend(_ *logical.BackendConfig) *Backend {
	var b Backend

	b.logger = slog.With(slog.String("component", "backend"))
	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        backendHelp,
		Paths: []*framework.Path{

			// api/register
			{
				Pattern:      "register",
				HelpSynopsis: "Registers a new user in vault",
				HelpDescription: `

Registers new user in vault using UUID. Generates mnemonics if not provided and store it in vault.
Returns randomly generated user UUID

`,
				Fields: map[string]*framework.FieldSchema{
					"username": {
						Type:        framework.TypeString,
						Description: "Username of new user (optional)",
						Default:     "",
					},
					"mnemonic": {
						Type:        framework.TypeString,
						Description: "Mnemonic of user (optional)",
						Default:     "",
					},
					"passphrase": {
						Type:        framework.TypeString,
						Description: "Passphrase of user (optional)",
						Default:     "",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathRegister,
				},
			},

			// api/sign
			{
				Pattern:         "sign",
				HelpSynopsis:    "Generate signature from raw transaction",
				HelpDescription: "Generates signature from stored mnemonic and passphrase using deviation path",
				Fields: map[string]*framework.FieldSchema{
					"uuid": {
						Type:        framework.TypeString,
						Description: "UUID of user",
					},
					"path": {
						Type:        framework.TypeString,
						Description: "Deviation path to obtain keys",
						Default:     "",
					},
					"coinType": {
						Type:        framework.TypeInt,
						Description: "Cointype of transaction",
					},
					"payload": {
						Type:        framework.TypeString,
						Description: "Raw transaction payload",
					},
					"isDev": {
						Type:        framework.TypeBool,
						Description: "Development mode flag",
						Default:     false,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathSign,
				},
			},

			// api/address
			{
				Pattern:         "address",
				HelpSynopsis:    "Generate address of user",
				HelpDescription: "Generates address from stored mnemonic and passphrase using deviation path",
				Fields: map[string]*framework.FieldSchema{
					"uuid": {
						Type:        framework.TypeString,
						Description: "UUID of user",
					},
					"path": {
						Type:        framework.TypeString,
						Description: "Deviation path to address",
						Default:     "",
					},
					"coinType": {
						Type:        framework.TypeInt,
						Description: "Cointype of transaction",
					},
					"isDev": {
						Type:        framework.TypeBool,
						Description: "Development mode flag",
						Default:     false,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAddress,
				},
			},

			// api/address/batch
			{
				Pattern:      "address/batch",
				HelpSynopsis: "Generate a batch of addresses for a user",
				HelpDescription: `

Generates a batch of addresses from stored mnemonic and passphrase using a templated derivation path.
(e.g., m/44'/60'/0'/0/%d).

`,
				Fields: map[string]*framework.FieldSchema{
					"uuid": {
						Type:        framework.TypeString,
						Description: "UUID of user",
					},
					"pathTemplate": {
						Type:        framework.TypeString,
						Description: "Templated derivation path, e.g., m/44'/60'/0'/0/%d",
					},
					"coinType": {
						Type:        framework.TypeInt,
						Description: "Cointype of transaction",
					},
					"startIndex": {
						Type:        framework.TypeInt,
						Description: "Start index for address generation",
						Default:     0,
					},
					"count": {
						Type:        framework.TypeInt,
						Description: "Number of addresses to generate",
					},
					"isDev": {
						Type:        framework.TypeBool,
						Description: "Development mode flag",
						Default:     false,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAddressBatch,
				},
			},

			// api/info
			{
				Pattern:      "info",
				HelpSynopsis: "Display information about this plugin",
				HelpDescription: `

Displays information about the plugin, such as the plugin version and where to
get help.

`,
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathInfo,
				},
			},
		},
	}
	return &b
}

const backendHelp = `
The API secrets engine serves as API for application server to store user information,
and optionally generate signed transaction from raw payload data.
`
