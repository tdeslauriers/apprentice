package permissions

import (
	"apprentice/internal/util"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Service is an interface that aggregates all permission services functionality
type Service interface {

	// GetAllPermissions returns all permissions from the database
	GetAllPermissions() ([]permissions.Permission, error)

	// GetUserPermissions returns the permissions for a given user/allowance account
	// returns a map of permissions and a slice of permissions so the calling function can choose which to use.
	// It returns an error if the permissions cannot be retrieved or if the user does not exist
	GetUserPermissions(username string) (map[string]permissions.Permission, []permissions.Permission, error)

	// CreatePermission creates a new permission in the database
	// It returns the created permission or an error if the permission could not be created
	CreatePermission(p *Permission) (*Permission, error)
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql data.SqlRepository, i data.Indexer) Service {
	return &service{
		db:      sql,
		indexer: i,
		// cryptor not needed thus far

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackagePermissions)).
			With(slog.String(util.ComponentKey, util.ComponentPermissions)),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface
type service struct {
	db      data.SqlRepository
	indexer data.Indexer

	logger *slog.Logger
}

// GetAllPermissions is the concrete implementation of the service method which
// returns all permissions from the database.
func (s *service) GetAllPermissions() ([]permissions.Permission, error) {

	qry := `SELECT
				uuid,
				name,
				service,
				description,
				created_at,
				active,
				slug
			FROM permission`
	var ps []permissions.Permission
	if err := s.db.SelectRecords(qry, &ps); err != nil {
		return nil, fmt.Errorf("failed to get permissions: %v", err)
	}

	if len(ps) < 1 {
		s.logger.Warn("no permissions found in database")
	}

	return ps, nil
}

// GetUserPermissions is the concrete implementation of the service method which
// returns the permissions for a given user/allowance account.
// It returns a map of permissions and a slice of permissions so the calling
// function can choose which to use.
// It returns an error if the permissions cannot be retrieved or if the user does not exist
func (s *service) GetUserPermissions(username string) (map[string]permissions.Permission, []permissions.Permission, error) {

	// validate is well formed email address: redundant, but good practice.
	if err := validate.IsValidEmail(username); err != nil {
		return nil, nil, err
	}

	// get blind index for user in allowance table
	index, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, nil, err
	}

	// get permissions for user in allowance table
	query := `SELECT
				p.uuid,
				p.name,
				p.service,
				p.description,
				p.created_at,
				p.active,
				p.slug
			FROM permission p
				LEFT OUTER JOIN allowance_permission ap ON p.uuid = ap.permission_uuid
				LEFT OUTER JOIN allowance a ON ap.allowance_uuid = a.uuid
			WHERE a.user_index = ?
				AND p.active = true`
	var ps []permissions.Permission
	if err := s.db.SelectRecords(query, &ps, index); err != nil {
		return nil, nil, err
	}

	if len(ps) < 1 {
		return nil, nil, fmt.Errorf("no permissions found for user %s", username)
	}

	// create a map of permissions
	psMap := make(map[string]permissions.Permission, len(ps))
	for _, p := range ps {
		psMap[p.Name] = p
	}

	// return the permissions
	return psMap, ps, nil
}

// CreatePermission is the concrete implementation of the service method which
// creates a new permission in the database.
// It returns the created permission or an error if the permission could not be created
func (s *service) CreatePermission(p *Permission) (*Permission, error) {

	// validate the permission
	// redundant, but good practice.
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid permission: %v", err)
	}

	// create uuid and set it in the permission record
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to create uuid for permission: %v", err)
	}
	p.Id = id.String()

	// create created_at timestamp and set it in the permission record
	now := time.Now().UTC()
	p.CreatedAt = data.CustomTime{Time: now}

	// create slug and set it in the permission record
	slug, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to create slug for permission: %v", err)
	}
	p.Slug = slug.String()

	// build the insert query
	query := `INSERT INTO permission (
				uuid,
				name,
				service,
				description,
				created_at,
				active,
				slug
			) VALUES (?, ?, ?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(query, p); err != nil {
		return nil, fmt.Errorf("failed to create permission: %v", err)
	}

	s.logger.Info(fmt.Sprintf("%s - %s created", p.Id, p.Name))

	return p, nil
}
