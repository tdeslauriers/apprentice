package permissions

import (
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
func NewAllowancePermissionsService(sql data.SqlRepository, i data.Indexer, c data.Cryptor) AllowancePermissionsService {
	return &allowancePermissionsService{
		db:      sql,
		indexer: i,
		cryptor: exo.NewPermissionCryptor(c),

		logger: slog.Default().With("service", "AllowancePermissionsService"),
	}
}

var _ AllowancePermissionsService = (*allowancePermissionsService)(nil)

type allowancePermissionsService struct {
	db      data.SqlRepository
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

	// get permissions for user in allowance table
	query := `
		SELECT
			p.uuid,
			p.service_name,
			p.permission,
			p.name,
			p.description,
			p.created_at,
			p.active,
			p.slug,
			p.slug_index
		FROM permission p
			LEFT OUTER JOIN allowance_permission ap ON p.uuid = ap.permission_uuid
			LEFT OUTER JOIN allowance a ON ap.allowance_uuid = a.uuid
		WHERE a.user_index = ?
			AND p.active = true`
	var ps []exo.PermissionRecord
	if err := s.db.SelectRecords(query, &ps, index); err != nil {
		return nil, nil, err
	}

	if len(ps) < 1 {
		return nil, nil, fmt.Errorf("no permissions found for user %s", username)
	}

	// decrypt and create a map of permissions
	psMap := make(map[string]exo.PermissionRecord, len(ps))
	for i, p := range ps {
		prepared, err := s.cryptor.DecryptPermission(p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to prepare permission %s: %v", p.Id, err)
		}
		ps[i] = *prepared
		psMap[p.Name] = *prepared
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
	qry := `INSERT INTO allowance_permission (id, allowance_uuid, permission_uuid, created_at) VALUES (?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, xref); err != nil {
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
	qry := `DELETE FROM allowance_permission WHERE allowance_uuid = ? AND permission_uuid = ?`
	if err := s.db.DeleteRecord(qry, allowanceId, permissionId); err != nil {
		return err
	}

	return nil
}
