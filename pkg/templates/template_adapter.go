package templates

import (
	"database/sql"
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// TemplateRepository defines the interface for template data operations.
type TemplateRepository interface {

	// FindActiveTemplates retrieves all active templates from the database including
	// their assignees.
	FindActiveTemplates() ([]TemplateAssignee, error)

	// FindTemplateAssignees retrieves a slice of a template joined to assignees by a template's slug
	FindTemplateAssignees(slug string) ([]TemplateAssignee, error)

	// InsertTemplate adds a new template record to the database.
	InsertTemplate(record TemplateRecord) error

	// InsertTemplateAllowanceXref adds a new xref record to the template_allowance table in the database.
	InsertTemplateAllowanceXref(xref AllowanceTemplateXref) error

	// InsertTemplateTaskXref adds a new xref record to the template_task table in the database.
	InsertTemplateTaskXref(xref TemplateTaskXref) error

	// UpdateTemplate updates an existing template record in the database.
	// Note: This takes a record struct, but will not update all fields: only
	// name, description, category, cadence, is_calculated, is_archived, and updated_at.
	UpdateTemplate(record TemplateRecord) error

	// DeleteTemplateAllowanceXref removes an xref record from the template_allowance table in the database.
	DeleteTemplateAllowanceXref(templateId, allowanceId string) error
}

// NewTemplateRepository creates a new instance of TemplateAdapter.
func NewTemplateRepository(db *sql.DB) TemplateRepository {
	return &templateAdapter{
		db: db,
	}
}

var _ TemplateRepository = (*templateAdapter)(nil)

// templateAdapter is a concrete implementation of TemplateRepository.
type templateAdapter struct {
	db *sql.DB
}

// FindActiveTemplates retrieves all active templates from the database.
func (a *templateAdapter) FindActiveTemplates() ([]TemplateAssignee, error) {

	qry := `
		SELECT 
			t.uuid, 
			t.name, 
			t.description, 
			t.cadence, 
			t.category, 
			t.is_calculated,
			t.slug AS template_slug, 
			t.created_at, 
			t.is_archived,
			a.username,
			a.slug AS allowance_slug
		FROM template t 
			LEFT OUTER JOIN template_allowance ta ON t.uuid = ta.template_uuid
			LEFT OUTER JOIN allowance a ON ta.allowance_uuid = a.uuid
		WHERE t.is_archived = FALSE`

	return data.SelectRecords[TemplateAssignee](a.db, qry)
}

// FindTemplateAssignees retrieves a slice of a template joined to assignees by a template's slug
func (a *templateAdapter) FindTemplateAssignees(slug string) ([]TemplateAssignee, error) {

	qry := `
		SELECT 
			t.uuid, 
			t.name, 
			t.description, 
			t.cadence, 
			t.category, 
			t.is_calculated,
			t.slug AS template_slug, 
			t.created_at, 
			t.is_archived,
			a.username,
			a.slug AS allowance_slug
		FROM template t 
			LEFT OUTER JOIN template_allowance ta ON t.uuid = ta.template_uuid
			LEFT OUTER JOIN allowance a ON ta.allowance_uuid = a.uuid
		WHERE t.slug = ?`

	ta, err := data.SelectRecords[TemplateAssignee](a.db, qry, slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("template record not found for slug: %s", slug)
		}
		return nil, fmt.Errorf("failed to retrieve template record from db: %v", err)
	}

	return ta, nil
}

// InsertTemplate adds a new template record to the database.
func (a *templateAdapter) InsertTemplate(record TemplateRecord) error {

	qry := `
		INSERT INTO template (
			uuid, 
			name, 
			description, 
			cadence, 
			category, 
			is_calculated, 
			slug, 
			created_at, 
			is_archived
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	return data.InsertRecord(a.db, qry, record)
}

// InsertTemplateAllowanceXref adds a new xref record to the template_allowance table in the database.
func (a *templateAdapter) InsertTemplateAllowanceXref(xref AllowanceTemplateXref) error {

	qry := `
		INSERT INTO template_allowance (
			id,
			template_uuid, 
			allowance_uuid, 
			created_at
		) VALUES (?, ?, ?, ?)`

	return data.InsertRecord(a.db, qry, xref)
}

// InsertTemplateTaskXref adds a new xref record to the template_task table in the database.
func (a *templateAdapter) InsertTemplateTaskXref(xref TemplateTaskXref) error {

	qry := `
		INSERT INTO template_task (
			id,
			template_uuid, 
			task_uuid, 
			created_at
		) VALUES (?, ?, ?, ?)`

	return data.InsertRecord(a.db, qry, xref)
}

// UpdateTemplate updates an existing template record in the database.
// Note: This takes a record struct, but will not update all fields: only
// name, description, category, cadence, is_calculated, is_archived, and updated_at.
func (a *templateAdapter) UpdateTemplate(record TemplateRecord) error {

	qry := `
		UPDATE template SET 
			name = ?, 
			description = ?, 
			cadence = ?, 
			category = ?, 
			is_calculated = ?, 
			is_archived = ?
		WHERE uuid = ?`

	return data.UpdateRecord(a.db, qry,
		record.Name,         // update
		record.Description,  // update
		record.Cadence,      // update
		record.Category,     // update
		record.IsCalculated, // update
		record.IsArchived,   // update
		record.Id,           // WHERE clause
	)
}

// DeleteTemplateAllowanceXref removes an xref record from the template_allowance table in the database.
func (a *templateAdapter) DeleteTemplateAllowanceXref(templateId, allowanceId string) error {

	qry := `
			DDELETE FROM template_allowance 
			WHERE template_uuid = ? 
				AND allowance_uuid = ?`

	return data.DeleteRecord(a.db, qry, templateId, allowanceId)
}
