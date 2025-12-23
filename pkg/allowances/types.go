package allowances

import (
	"database/sql"
	"fmt"

	"github.com/tdeslauriers/apprentice/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

const (

	// 401
	ErrAccountExists = "allowance account already exists"

	// 404
	ErrAllowanceNotFound = "allowance account not found"

	// 422
	ErrInvalidUsername      = "invalid username"
	ErrInvalidAllowanceSlug = "invalid allowance slug"

	// 500
	ErrGenIndex = "failed to obtain/generate blind index"
)

// Handler is an aggregate interface for all allowances handler functionality
type Handler interface {
	AllowancesHandler
	AccountHandler
	AllowancePermissionsHandler
}

// NewHandler creates a new Handler interface, returning a pointe(s) to the concrete implementation(s)
func NewHandler(
	s Service,
	p permissions.Service,
	s2s jwt.Verifier,
	iam jwt.Verifier,
	tkn provider.S2sTokenProvider,
	identity *connect.S2sCaller,
) Handler {

	return &handler{
		AllowancesHandler:           NewAllowancesHandler(s, p, s2s, iam, tkn, identity),
		AllowancePermissionsHandler: NewAllowancePermissionsHandler(s, s2s, iam),
		AccountHandler:              NewAccountHandler(s, p, s2s, iam),
	}
}

var _ Handler = (*handler)(nil)

// handler is the concrete implementation of the Handler interface
type handler struct {
	AllowancesHandler
	AccountHandler
	AllowancePermissionsHandler
}

// Service is an aggregate interface for all allowances service functionality
type Service interface {
	AllowancePermissionsService
	AllowanceService
	AllowanceErrorService
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql *sql.DB, i data.Indexer, c data.Cryptor) Service {
	return &service{
		AllowancePermissionsService: NewAllowancePermissionsService(sql, i, c),
		AllowanceService:            NewAllowanceService(sql, i, c),
		AllowanceErrorService:       NewAllowanceErrorService(),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface
type service struct {
	AllowancePermissionsService
	AllowanceService
	AllowanceErrorService
}

// Allowance is a struct that represents a user's allowance as it exists in the database.
// It can also be used for json, though the indexes will be omitted.
// Balance is counted in cents to avoid Superman 3 style errors.
type Allowance struct {
	Id           string                 `json:"id,omitempty" db:"uuid"`
	Balance      uint64                 `json:"balance" db:"balance"`
	Username     string                 `json:"username,omitempty" db:"username"`
	UserIndex    string                 `json:"user_index,omitempty" db:"user_index"`
	Slug         string                 `json:"slug,omitempty" db:"slug"`
	SlugIndex    string                 `json:"slug_index,omitempty" db:"slug_index"`
	CreatedAt    data.CustomTime        `json:"created_at" db:"created_at"`
	UpdatedAt    data.CustomTime        `json:"updated_at" db:"updated_at"`
	IsArchived   bool                   `json:"is_archived" db:"is_archived"`
	IsActive     bool                   `json:"is_active" db:"is_active"`
	IsCalculated bool                   `json:"is_calculated" db:"is_calculated"`
	Permissions  []exo.PermissionRecord `json:"permissions,omitempty" `
}

func (a *Allowance) ValidateCmd() error {
	if a.Id != "" && !validate.IsValidUuid(a.Id) {
		return fmt.Errorf("invalid or not well formatted allowance id")
	}

	if a.Username != "" {
		if len(a.Username) < validate.EmailMin || len(a.Username) > validate.EmailMax {
			return fmt.Errorf("invalid username: must be greater than %d and less than %d characters long", validate.EmailMin, validate.EmailMax)
		}

		if err := validate.IsValidEmail(a.Username); err != nil {
			return fmt.Errorf("invalid username: %v", err)
		}
	}

	if a.Slug != "" && !validate.IsValidUuid(a.Slug) {
		return fmt.Errorf("invalid or not well formatted slug")
	}

	return nil
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
	Balance      string          `db:"balance"`  // encrypted string vs decrypted float64 in db
	Username     string          `db:"username"` // encrypted email in db
	UserIndex    string          `db:"user_index"`
	Slug         string          `db:"slug"` // encrypted slug in db
	SlugIndex    string          `db:"slug_index"`
	CreatedAt    data.CustomTime `db:"created_at"`
	UpdatedAt    data.CustomTime `db:"updated_at"`
	IsArchived   bool            `db:"is_archived"`
	IsActive     bool            `db:"is_active"`
	IsCalculated bool            `db:"is_calculated"`
}

// UpdateAllowanceCmd is a struct that represents the command to update an allowance in the allownace service.
// It does not represent a data model in the database.
type UpdateAllowanceCmd struct {
	Csrf string `json:"csrf,omitempty"`

	Credit       uint64 `json:"credit"`
	Debit        uint64 `json:"debit"`
	IsArchived   bool   `json:"is_archived"`
	IsActive     bool   `json:"is_active"`
	IsCalculated bool   `json:"is_calculated"`
}

// ValidateCmd validates the UpdateAllowanceCmd struct
// Note: it does not include any business logic validation, only data validation.
func (u *UpdateAllowanceCmd) ValidateCmd() error {
	if u.Csrf != "" {
		if !validate.IsValidUuid(u.Csrf) {
			return fmt.Errorf("invalid csrf token submitted with request")
		}
	}

	if u.Credit > 1000000 {
		return fmt.Errorf("invalid credit: must be less than or equal to $10,000, since that is ridiculous")
	}

	if u.Debit > 1000000 {
		return fmt.Errorf("invalid debit: must be less than or equal to $10,000, since that is ridiculous")
	}

	// validation of boolean values is not necessary: business logic will determine if they are valid in service.
	return nil
}
