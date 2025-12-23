package allowances

import (
	"database/sql"

	"github.com/tdeslauriers/apprentice/internal/permissions"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
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
