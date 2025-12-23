package permissions

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// AllowancePermissionsService defines the interface for managing permissions related to allowances
type AllowancePermissionsService interface {

	// GetAllowancePermissions returns the permissions for a given user/allowance account
	// returns a map of permissions and a slice of permissions so the calling function can choose which to use.
	// It returns an error if the permissions cannot be retrieved or if the user does not exist
	GetAllowancePermissions(username string) (map[string]exo.PermissionRecord, []exo.PermissionRecord, error)

	// AddPermissionToAllowance ties a permission to an allowance account via xref table in the database
	AddPermissionToAllowance(allowanceId, permissionId string) error

	// RemovePermissionFromAllowance removes a permission from an allowance account
	// by removing the xref record from the database
	RemovePermissionFromAllowance(allowanceId, permissionId string) error
}

// NewAllowancePermissionsService creates a new AllowancePermissionsService interface
// and retunrs a pointer to a concerte implementation of the interface
func NewAllowancePermissionsService(sql *sql.DB, i data.Indexer, c data.Cryptor) AllowancePermissionsService {
	return &allowancePermissionsService{
		db:      NewAllowancePermissionsRepository(sql),
		indexer: i,
		cryptor: exo.NewPermissionCryptor(c),

		logger: slog.Default().With("service", "AllowancePermissionsService"),
	}
}

var _ AllowancePermissionsService = (*allowancePermissionsService)(nil)

type allowancePermissionsService struct {
	db      AllowancePermissionsRepository
	indexer data.Indexer
	cryptor exo.PermissionCryptor

	logger *slog.Logger
}

// GetAllowancePermissions is the concrete implementation of the service method which
// returns the permissions for a given user/allowance account.
// It returns a map of permissions and a slice of permissions so the calling
// function can choose which to use.
// It returns an error if the permissions cannot be retrieved or if the user does not exist
func (s *allowancePermissionsService) GetAllowancePermissions(username string) (map[string]exo.PermissionRecord, []exo.PermissionRecord, error) {

	// validate is well formed email address: redundant, but good practice.
	if err := validate.IsValidEmail(username); err != nil {
		return nil, nil, err
	}

	// get blind index for user in allowance table
	index, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, nil, err
	}

	// get permissions for user from database by user index
	ps, err := s.db.FindAllowancePermissions(index)
	if err != nil {
		return nil, nil, err
	}

	// It is possible for patrons to have zero permissions.
	// This will be the default case, so we return an empty map and slice.
	if len(ps) < 1 {
		s.logger.Warn(fmt.Sprintf("no permissions found for allowance account with username %s", username))
	}

	// decrypt and create a map of permissions
	psMap := make(map[string]exo.PermissionRecord, len(ps))
	for i, p := range ps {
		prepared, err := s.cryptor.DecryptPermission(p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to prepare permission %s: %v", p.Id, err)
		}
		ps[i] = *prepared
		psMap[prepared.Permission] = *prepared
	}

	// return the permissions
	return psMap, ps, nil
}

// AddPermissionToAllowance is the concrete implementation of the service method which
// adds a permission to an allowance account by creating a record in the xref table.
func (s *allowancePermissionsService) AddPermissionToAllowance(allowanceId, permissionId string) error {

	// validate the allowanceId and permissionId are well formed uuids
	if !validate.IsValidUuid(allowanceId) {
		return fmt.Errorf("invalid allowance id: %s", allowanceId)
	}
	if !validate.IsValidUuid(permissionId) {
		return fmt.Errorf("invalid permission id: %s", permissionId)
	}

	// build the xref record to insert
	xref := AllowancePermissionRecord{
		Id:           0, // auto-incremented by the database
		AllowanceId:  allowanceId,
		PermissionId: permissionId,
		CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
	}

	// insert the xref record into the database
	if err := s.db.InsertAllowancePermissionXref(xref); err != nil {
		return fmt.Errorf("failed to add permission %s to allowance %s: %v", permissionId, allowanceId, err)
	}

	return nil
}

// RemovePermissionFromAllowance is the concrete implementation of the service method which
// removes a permission from an allowance account by removing the xref record from the database.
func (s *allowancePermissionsService) RemovePermissionFromAllowance(allowanceId, permissionId string) error {

	// validate the allowanceId and permissionId are well formed uuids
	if !validate.IsValidUuid(allowanceId) {
		return fmt.Errorf("invalid allowance id: %s", allowanceId)
	}
	if !validate.IsValidUuid(permissionId) {
		return fmt.Errorf("invalid permission id: %s", permissionId)
	}

	// delete the xref record from the database
	if err := s.db.DeleteAllowancePermissionXref(allowanceId, permissionId); err != nil {
		return err
	}

	return nil
}
