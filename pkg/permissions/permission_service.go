package permissions

import (
	"apprentice/internal/util"
	"fmt"
	"log/slog"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Service is an interface that aggregates all permission services functionality
type Service interface {

	// GetPermissions returns the permissions for a given user/allowance account
	// returns a map of permissions and a slice of permissions so the calling function can choose which to use.
	// It returns an error if the permissions cannot be retrieved or if the user does not exist
	GetPermissions(username string) (map[string]permissions.Permission, []permissions.Permission, error)
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

// GetPermissions is the concrete implementation of the service method which
// returns the permissions for a given user/allowance account.
// It returns a map of permissions and a slice of permissions so the calling
// function can choose which to use.
// It returns an error if the permissions cannot be retrieved or if the user does not exist
func (s *service) GetPermissions(username string) (map[string]permissions.Permission, []permissions.Permission, error) {

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
				p.description,
				p.created_at,
				p.active,
				p.slug
			FROM permission p
				LEFT OUTER JOIN allowance_permission ap ON p.uuid = ap.permission_uuid
				LEFT OUTER JOIN allowance a ON ap.allowance_uuid = a.uuid
			WHERE a.user_index = ?`
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
