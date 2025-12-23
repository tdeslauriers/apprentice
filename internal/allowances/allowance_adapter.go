package allowances

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// AllowanceRepository defines the interface for allowances data operations.
type AllowanceRepository interface {

	// FindAll retrieves all allowance records.
	// Note: records will still be encrypted
	FindAll() ([]AllowanceRecord, error)

	// FindExistsByUser checks if an allowance record exists for a given user index.
	FindExistsByUser(userIndex string) (bool, error)

	// FindByIndex retrieves an allowance record by its slug index.
	// Note: record will still be encrypted
	FindBySlugIndex(index string) (*AllowanceRecord, error)

	// FindByUserIndex retrieves an allowance record by its user index.
	// Note: record will still be encrypted
	FindByUserIndex(index string) (*AllowanceRecord, error)

	// FindUsersByIndices retrieves allowance records for multiple user indices.
	// Note: records will still be encrypted
	FindUsersByIndices(indices []string) ([]AllowanceRecord, error)

	// InsertAllowance adds a new allowance record to the database.
	// Note: you must ensure the record is encrypted calling this method.
	InsertAllowance(record AllowanceRecord) error

	// UpdateAllowance updates an existing allowance record in the database.
	// Note: you must ensure the record is encrypted calling this method.
	// This takes a record struct, but will not update all fields: only
	// balance, is_archived, is_active, is_calculated, and updated_at.
	UpdateAllowance(record AllowanceRecord) error
}

// NewAllowanceRepository creates a new instance of AllowanceAdapter.
func NewAllowanceRepository(db *sql.DB) AllowanceRepository {
	return &allowanceAdapter{
		sql: db,
	}
}

var _ AllowanceRepository = (*allowanceAdapter)(nil)

// allowanceAdapter is a concrete implementation of AllowanceAdapter.
type allowanceAdapter struct {
	sql *sql.DB
}

// FindAll retrieves all allowances from the database.
// Note: these records will still be encrypted
func (a *allowanceAdapter) FindAll() ([]AllowanceRecord, error) {

	// get all allowance accounts
	qry := `
		SELECT 
			uuid, 
			balance, 
			username,
			user_index,
			slug, 
			slug_index,
			created_at,
			updated_at,
			is_archived, 
			is_active, 
			is_calculated
		FROM allowance`

	records, err := data.SelectRecords[AllowanceRecord](a.sql, qry)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// FindExistsByUser checks if an allowance exists for a given user index.
func (a *allowanceAdapter) FindExistsByUser(userIndex string) (bool, error) {

	qry := `
		SELECT EXISTS(
			SELECT 1 
			FROM allowance 
			WHERE user_index = ?
		) AS record_exists`

	return data.SelectExists(a.sql, qry, userIndex)
}

// FindByIndex retrieves an allowance by its slug index.
// Note: this record will still be encrypted
func (a *allowanceAdapter) FindBySlugIndex(index string) (*AllowanceRecord, error) {

	qry := `
		SELECT 
			uuid, 
			balance, 
			username,
			user_index,
			slug, 
			slug_index,
			created_at,
			updated_at,
			is_archived, 
			is_active, 
			is_calculated
		FROM allowance
		WHERE slug_index = ?`

	record, err := data.SelectOneRecord[AllowanceRecord](a.sql, qry, index)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("allowance account not found")
		}
		return nil, err
	}

	return &record, nil
}

// FindByUserIndex retrieves all allowances for a given user index.
// Note: these records will still be encrypted
func (a *allowanceAdapter) FindByUserIndex(index string) (*AllowanceRecord, error) {

	qry := `
		SELECT 
			uuid, 
			balance, 
			username,
			user_index,
			slug, 
			slug_index,
			created_at,
			updated_at,
			is_archived, 
			is_active, 
			is_calculated
		FROM allowance
		WHERE user_index = ?`

	record, err := data.SelectOneRecord[AllowanceRecord](a.sql, qry, index)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("allowance account not found")
		}
		return nil, err
	}

	return &record, nil
}

// FindUsersByIndices retrieves allowance records for multiple user indices.
// Note: these records will still be encrypted
func (a *allowanceAdapter) FindUsersByIndices(indices []string) ([]AllowanceRecord, error) {

	// handle empty input
	if len(indices) == 0 {
		return nil, errors.New("user indices slice cannot be empty.")
	}

	// convert string slice of indexes to args ...interface{}
	placeholders := make([]string, len(indices))
	args := make([]interface{}, len(indices))
	for i, index := range indices {
		placeholders[i] = "?"
		args[i] = index
	}

	// build query using allowance account user indices placeholders fo IN clause
	qry := fmt.Sprintf(`
		SELECT 
			uuid, 
			balance, 
			username,
			user_index,
			slug, 
			slug_index,
			created_at,
			updated_at,
			is_archived, 
			is_active, 
			is_calculated
		FROM allowance
		WHERE user_index IN (%s)`, strings.Join(placeholders, ","))

	records, err := data.SelectRecords[AllowanceRecord](a.sql, qry, args...)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// InsertAllowance adds a new allowance record to the database.
// Note: you must ensure the record is encrypted calling this method.
func (a *allowanceAdapter) InsertAllowance(record AllowanceRecord) error {

	qry := `
		INSERT INTO allowance (
			uuid, 
			balance, 
			username, 
			user_index, 
			slug, 
			slug_index, 
			created_at, 
			updated_at,
			is_archived, 
			is_active, 
			is_calculated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	if err := data.InsertRecord(a.sql, qry, record); err != nil {
		return err
	}

	return nil
}

// UpdateAllowance updates an existing allowance record in the database.
// Note: you must ensure the record is encrypted calling this method.
// This takes a record struct, but will not update all fields: only
// balance, is_archived, is_active, is_calculated, and updated_at.
func (a *allowanceAdapter) UpdateAllowance(record AllowanceRecord) error {

	qry := `
		UPDATE allowance
		SET balance = ?,
			updated_at = ?,
			is_archived = ?,
			is_active = ?,
			is_calculated = ?
		WHERE slug_index = ?`

	if err := data.UpdateRecord(
		a.sql,
		qry,
		record.Balance,      // to update
		record.UpdatedAt,    // to update
		record.IsArchived,   // to update
		record.IsActive,     // to update
		record.IsCalculated, // to update
		record.SlugIndex,    // for lookup/WHERE clause
	); err != nil {
		return err
	}

	return nil
}
