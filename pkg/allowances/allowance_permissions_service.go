package allowances

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/tdeslauriers/apprentice/internal/util"
	"github.com/tdeslauriers/apprentice/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// AllowancePermissionsService defines the interface for managing permissions related to allowances
type AllowancePermissionsService interface {

	// GetAllowancePermissions returns the permissions for a given user/allowance account
	// NOTE: at this time, this is a wrapper around the permissions service's functionality with
	// the same name.
	GetAllowancePermissions(username string) (map[string]exo.PermissionRecord, []exo.PermissionRecord, error)

	// UpdateAllowancePermissions updates the permissions for a given user/allowance account in the datebase
	// It returns a map of added permissions, removed permissions, and an error if the update fails.
	// Slugs are the slugs for the permission records.
	UpdateAllowancePermissions(ctx context.Context, a *Allowance, slugs []string) (map[string]exo.PermissionRecord, map[string]exo.PermissionRecord, error)
}

// NewAllowancePermissionsService creates a new AllowancePermissionsService interface
// and returns a pointer to a concrete implementation of the interface
func NewAllowancePermissionsService(sql data.SqlRepository, i data.Indexer, c data.Cryptor) AllowancePermissionsService {
	return &allowancePermissionsService{
		db:         sql,
		permission: permissions.NewService(sql, i, c),

		logger: slog.Default().
			With(util.PackageKey, util.PackageAllowances).
			With(util.ComponentKey, util.ComponentAllowancesPermissionsService),
	}
}

var _ AllowancePermissionsService = (*allowancePermissionsService)(nil)

type allowancePermissionsService struct {
	db data.SqlRepository

	permission permissions.Service

	logger *slog.Logger
}

// GetAllowancePermissions is the concrete implementation of the service method which
// returns the permissions for a given user/allowance account.
// NOTE: at this time, this is a wrapper around the permissions service's functionality with
// the same name.
func (s *allowancePermissionsService) GetAllowancePermissions(username string) (map[string]exo.PermissionRecord, []exo.PermissionRecord, error) {

	return s.permission.GetAllowancePermissions(username)
}

// UpdateAllowancePermissions is the concrete implementation of the service method which
// updates the permissions for a given user/allowance account in the database.
// It returns a map of added permissions, removed permissions, and an error if the update fails
func (s *allowancePermissionsService) UpdateAllowancePermissions(ctx context.Context, a *Allowance, slugs []string) (map[string]exo.PermissionRecord, map[string]exo.PermissionRecord, error) {

	// create local log to hold telmetry from context
	// get telemetry from context -> set up log
	log := s.logger
	telemetry, ok := ctx.Value(connect.TelemetryKey).(*connect.Telemetry)
	if ok && telemetry != nil {
		log = log.With(telemetry.TelemetryFields()...)
	} else {
		log.Warn("failed to retrieve telemetry from context for GetAccessToken")
	}

	if a == nil {
		return nil, nil, fmt.Errorf("allowance account cannot be nil")
	}

	//validate the permission slugs are well formed uuids
	for _, slug := range slugs {
		if !validate.IsValidUuid(slug) {
			return nil, nil, fmt.Errorf("invalid permission slug: %s", slug)
		}
	}

	// get map of all permissions in the database
	all, _, err := s.permission.GetAllPermissions()
	if err != nil {
		return nil, nil, err
	}

	// build the updated map of permissions
	// return an error if any slug is not found in the list of all permissions from teh database
	// key is the permission record's slug
	updated := make(map[string]exo.PermissionRecord, len(slugs))
	for _, slug := range slugs {
		if p, ok := all[slug]; ok {
			updated[slug] = p
		} else {
			return nil, nil, fmt.Errorf("permission slug %s not found in database", slug)
		}
	}

	// build a map of the current permissions for the allowance account
	// key is the permission record's slug
	current := make(map[string]exo.PermissionRecord, len(a.Permissions))
	for _, p := range a.Permissions {
		current[p.Slug] = p
	}

	// build a map of the permissions to add to the allowance account
	toAdd := make(map[string]exo.PermissionRecord, len(updated))
	for slug, pm := range updated {
		if _, exists := current[slug]; !exists {
			toAdd[slug] = pm
		}
	}

	// build a map of the permissions to remove from the allowance account
	toRemove := make(map[string]exo.PermissionRecord, len(current))
	for slug, pm := range current {
		if _, exists := updated[slug]; !exists {
			toRemove[slug] = pm
		}
	}

	// return early if there are no permissions to add or remove
	if len(toAdd) == 0 && len(toRemove) == 0 {
		log.Warn(fmt.Sprintf("no changes to permissiosns for allowance account %s", a.Username))
		return nil, nil, nil
	}

	var (
		wg    sync.WaitGroup
		errCh = make(chan error, len(toAdd)+len(toRemove))
	)

	// add the permissions to the allowance account if applicable
	if len(toAdd) > 0 {
		for _, pm := range toAdd {
			wg.Add(1)
			go func(permission exo.PermissionRecord, eCh chan<- error, wg *sync.WaitGroup) {
				defer wg.Done()

				if err := s.permission.AddPermissionToAllowance(a.Id, permission.Id); err != nil {
					eCh <- fmt.Errorf("failed to add permission %s to allowance account %s: %v", permission.Slug, a.Username, err)
				}

				log.Info(fmt.Sprintf("added permission '%s' to allowance account '%s'", permission.Name, a.Username))
			}(pm, errCh, &wg)
		}
	}

	// remove the permissions from the allowance account if applicable
	if len(toRemove) > 0 {
		for _, pm := range toRemove {
			wg.Add(1)
			go func(permission exo.PermissionRecord, eCh chan<- error, wg *sync.WaitGroup) {
				defer wg.Done()

				if err := s.permission.RemovePermissionFromAllowance(a.Id, permission.Id); err != nil {
					eCh <- fmt.Errorf("failed to remove permission %s from allowance account %s: %v", permission.Slug, a.Username, err)
				}

				log.Info(fmt.Sprintf("removed permission '%s' from allowance account '%s'", permission.Name, a.Username))
			}(pm, errCh, &wg)
		}
	}

	wg.Wait()
	close(errCh)

	// handle any errors that occurred during update go routine execution
	if len(errCh) > 0 {
		var errs []error
		for err := range errCh {
			errs = append(errs, err)
		}
		return nil, nil, fmt.Errorf("failed to update permissions for allowance account %s: %s", a.Username, errors.Join(errs...))
	}

	return toAdd, toRemove, nil
}
