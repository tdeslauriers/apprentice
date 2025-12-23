package permissions

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
)

// AllowancePermissionsRepository defines the interface for allowance permissions data operations.
type AllowancePermissionsRepository interface {

	// FindAllowancePermissions retrieves allowance user/account's permissions from the database.
	// Note: this implementation is only returns active permissions.
	FindAllowancePermissions(userIndex string) ([]exo.PermissionRecord, error)

	// InsertAllowancePermissionXref adds a new  xref record to the allowance_permission table in the database.
	InsertAllowancePermissionXref(xref AllowancePermissionRecord) error

	// DeleteAllowancePermissionXref removes an xref record from the allowance_permission table in the database.
	DeleteAllowancePermissionXref(allowanceId, permissionId string) error
}

// NewAllowancePermissionsRepository creates a new instance of AllowancePermissionsAdapter.
func NewAllowancePermissionsRepository(db *sql.DB) AllowancePermissionsRepository {
	return &allowancePermissionsAdapter{
		sql: db,
	}
}

var _ AllowancePermissionsRepository = (*allowancePermissionsAdapter)(nil)

// allowancePermissionsAdapter is a concrete implementation of AllowancePermissionsRepository.
type allowancePermissionsAdapter struct {
	sql *sql.DB
}

// FindAllowancePermissions retrieves allowance user/account's permissions from the database.
// Note: this implementation is only returns active permissions.
func (a *allowancePermissionsAdapter) FindAllowancePermissions(userIndex string) ([]exo.PermissionRecord, error) {

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

	return data.SelectRecords[exo.PermissionRecord](a.sql, query, userIndex)
}

// InsertAllowancePermissionXref adds a new  xref record to the allowance_permission table in the database.
func (a *allowancePermissionsAdapter) InsertAllowancePermissionXref(xref AllowancePermissionRecord) error {

	qry := `
		INSERT INTO allowance_permission (
			id, 
			allowance_uuid, 
			permission_uuid, 
			created_at
		) VALUES (?, ?, ?, ?)`

	return data.InsertRecord(a.sql, qry, xref)
}

// DeleteAllowancePermissionXref removes an xref record from the allowance_permission table in the database.
func (a *allowancePermissionsAdapter) DeleteAllowancePermissionXref(allowanceId, permissionId string) error {

	qry := `
			DELETE FROM allowance_permission 
			WHERE allowance_uuid = ? 
				AND permission_uuid = ?`

	return data.DeleteRecord(a.sql, qry, allowanceId, permissionId)
}
