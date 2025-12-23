package tasks

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// Service is an interface that aggregates all task services functionality
type Service interface {
	TaskService
	TaskErrorService
	ScheduledService
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql *sql.DB, i data.Indexer, c data.Cryptor) Service {
	return &service{
		TaskService:      NewTaskService(sql, i, c),
		TaskErrorService: NewTaskErrorService(),
		ScheduledService: NewScheduledService(sql),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface
type service struct {
	TaskService
	TaskErrorService
	ScheduledService
}

// TaskRecord is a struct that represents a task record in the database
type TaskRecord struct {
	Id             string          `db:"uuid" json:"id,omitempty"`
	CreatedAt      data.CustomTime `db:"created_at" json:"created_at,omitempty"`
	IsComplete     bool            `db:"is_complete" json:"is_complete"`
	CompletedAt    sql.NullTime    `db:"completed_at" json:"completed_at,omitempty"`
	IsSatisfactory bool            `db:"is_satisfactory" json:"is_satisfactory"`
	IsProactive    bool            `db:"is_proactive" json:"is_proactive"`
	Slug           string          `db:"slug" json:"slug,omitempty"`
	IsArchived     bool            `db:"is_archived" json:"is_archived"`
}

// TaskAllowanceXref is a model that represents a many-to-many relationship
// between tasks and allowances in the db
type TaskAllowanceXref struct {
	Id          int             `db:"id" json:"id,omitempty"`
	TaskId      string          `db:"task_uuid" json:"task_uuid,omitempty"`
	AllowanceId string          `db:"allowance_uuid" json:"allowance_uuid,omitempty"`
	CreatedAt   data.CustomTime `db:"created_at" json:"created_at,omitempty"`
}

// TaskGeneration is a model for a join representing the data needed to create a task
// with all of it's xref data and check if the tasks already exists
// NOTE: it is for creating tasks so most of it's fields are from the task template,
// allowance, and xref tables
type TaskGeneration struct {
	TemplateId  string `db:"template_uuid"`  // Template record uuid
	AllowanceId string `db:"allowance_uuid"` // Allowance record uuid
}

// TemplateTaskXref is a model that represents a many-to-many relationship
type TemplateTaskXref struct {
	Id         int             `db:"id"`
	TemplateId string          `db:"template_uuid"`
	TaskId     string          `db:"task_uuid"`
	CreatedAt  data.CustomTime `db:"created_at"`
}
