package allowances

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (

	// 401
	ErrAccountExists = "allowance account already exists"

	// 404
	ErrAllowanceNotFound = "allowance account not found"

	// 422
	ErrInvalidUsername           = "invalid username"
	ErrInvalidAllowanceSlug      = "invalid allowance slug"
	
	// 500
	ErrGenIndex = "failed to obtain/generate blind index"
)

// Handler is an aggregate interface for all allowances handler functionality
type Handler interface {
	AllowancesHandler
}

// NewHandler creates a new Handler interface, returning a pointe(s) to the concrete implementation(s)
func NewHandler(s Service, s2s, iam jwt.Verifier, tkn provider.S2sTokenProvider, identity connect.S2sCaller) Handler {
	return &handler{
		AllowancesHandler: NewAllowancesHandler(s, s2s, iam, tkn, identity),
	}
}

var _ Handler = (*handler)(nil)

// handler is the concrete implementation of the Handler interface
type handler struct {
	AllowancesHandler
}

// Service is an aggregate interface for all allowances service functionality
type Service interface {
	AllowanceService
	AllowanceErrorService
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql data.SqlRepository, i data.Indexer, c data.Cryptor) Service {
	return &service{
		AllowanceService:      NewAllowanceService(sql, i, c),
		AllowanceErrorService: NewAllowanceErrorService(),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface
type service struct {
	AllowanceService
	AllowanceErrorService
}

// CreateAllowanceCmd is the model command to create a new allowance account
type CreateAllowanceCmd struct {
	Username  string `json:"username"`
	Slug      string `json:"slug"`
	BirthDate string `json:"birth_date"`
}

// ValidateCmd performs input validation check on allowance account creation fields.
func (c *CreateAllowanceCmd) ValidateCmd() error {

	if err := validate.IsValidEmail(c.Username); err != nil {
		return fmt.Errorf("invalid username: %v", err)
	}

	if !validate.IsValidUuid(c.Slug) {
		return fmt.Errorf("invalid slug")
	}

	if err := validate.IsValidBirthday(c.BirthDate); err != nil {
		return fmt.Errorf("invalid birth date: %v", err)
	}

	return nil
}

// AllowanceRecord is a model for an allowance account db record which has different types than the service model
// or json model because the balance is stored as an ecrypted string in the db
type AllowanceRecord struct {
	Id           string          `db:"uuid"`
	Balance      string          `db:"balance"` // encrypted string vs decrypted float64
	Username     string          `db:"username"`
	UserIndex    string          `db:"user_index"`
	Slug         string          `db:"slug"`
	SlugIndex    string          `db:"slug_index"`
	CreatedAt    data.CustomTime `db:"created_at"`
	UpdatedAt    data.CustomTime `db:"updated_at"`
	IsArchived   bool            `db:"is_archived"`
	IsActive     bool            `db:"is_active"`
	IsCalculated bool            `db:"is_calculated"`
}
