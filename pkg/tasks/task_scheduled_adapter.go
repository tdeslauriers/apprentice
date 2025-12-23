package tasks

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// ScheduledRepository is an interface that defines the methods for interacting with scheduled task data in persistence.
type ScheduledRepository interface {

	// TaskExistsByCadence checks if tasks exist by cadence, ie, has it already been created
	// by another service instance.
	TaskExistsByCadence(cadence Cadence) (bool, error)

	// FindTemplates retrieves templates by cadence for scheduled task generation.
	FindTemplates(cadence Cadence) ([]TaskGeneration, error)

	// InsertTaskRecord adds a new task record to the database.
	InsertTaskRecord(record TaskRecord) error

	// InsertTemplateTaskXref adds a new xref record to the template_task table in the database.
	InsertTemplateTaskXref(xref TemplateTaskXref) error

	// InsertTaskAllowanceXref adds a new xref record to the task_allowance table in the database.
	InsertTaskAllowanceXref(xref TaskAllowanceXref) error
}

// NewScheduledRepository creates a new instance of ScheduledAdapter.
func NewScheduledRepository(db *sql.DB) ScheduledRepository {

	return &scheduledAdapter{
		sql: db,
	}
}

var _ ScheduledRepository = (*scheduledAdapter)(nil)

// scheduledAdapter is a concrete implementation of ScheduledRepository.
type scheduledAdapter struct {
	sql *sql.DB
}

// TaskExistsByCadence checks if tasks exist by cadence, ie, has it already been created
// by another service instance.
func (s *scheduledAdapter) TaskExistsByCadence(cadence Cadence) (bool, error) {

	qry := `
		SELECT EXISTS (
			SELECT 1 
			FROM task t
				LEFT OUTER JOIN template_task tt ON t.uuid = tt.task_uuid
				LEFT OUTER JOIN template tem ON tt.template_uuid = tem.uuid
			WHERE tem.cadence = ?
				AND t.created_at >= UTC_TIMESTAMP() - INTERVAL 2 HOUR
		)` // using 2 hours to account for task creation jitter

	return data.SelectExists(s.sql, qry, string(cadence))
}

// FindTemplates retrieves templates by cadence for scheduled task generation.
func (s *scheduledAdapter) FindTemplates(cadence Cadence) ([]TaskGeneration, error) {

	qry := `
		SELECT 
			t.uuid AS template_uuid,
			ta.allowance_uuid AS allowance_uuid
		FROM template t
			LEFT OUTER JOIN template_allowance ta ON t.uuid = ta.template_uuid
		WHERE t.cadence = ?
			AND t.is_archived = false`

	return data.SelectRecords[TaskGeneration](s.sql, qry, string(cadence))
}

// InsertTaskRecord adds a new task record to the database.
func (s *scheduledAdapter) InsertTaskRecord(record TaskRecord) error {

	qry := `
		INSERT INTO task (
			uuid, 
			created_at, 
			is_complete, 
			completed_at, 
			is_satisfactory, 
			is_proactive, 
			slug, 
			is_archived
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	return data.InsertRecord(s.sql, qry, record)
}

// InsertTemplateTaskXref adds a new xref record to the template_task table in the database.
func (s *scheduledAdapter) InsertTemplateTaskXref(xref TemplateTaskXref) error {

	qry := `
		INSERT INTO template_task (
			id, 
			template_uuid, 
			task_uuid, 
			created_at
		) VALUES (?, ?, ?, ?)`

	return data.InsertRecord(s.sql, qry, xref)
}

// InsertTaskAllowanceXref adds a new xref record to the task_allowance table in the database.
func (s *scheduledAdapter) InsertTaskAllowanceXref(xref TaskAllowanceXref) error {

	qry := `
		INSERT INTO task_allowance (
			id, 
			task_uuid, 
			allowance_uuid, 
			created_at
		) VALUES (?, ?, ?, ?)`

	return data.InsertRecord(s.sql, qry, xref)
}
