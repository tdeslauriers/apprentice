package tasks

import (
	"database/sql"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/tasks"
)

// Service is an interface that aggregates all task services functionality
type Service interface {
	TaskService
	TaskErrorService
	ScheduledService
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql data.SqlRepository, i data.Indexer, c data.Cryptor) Service {
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

// Task is a struct that represents a task record in the database
type Task struct {
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

// TaskRecord is a struct that represents a task-template join/composite record in the database
// Note: is interchangeable json object with carapace pkg/tasks.Task
type TaskRecord struct {
	Id             string          `json:"id,omitempty" db:"uuid"`                   // Tasks record uuid
	Name           string          `json:"name" db:"name"`                           // Task template name
	Description    string          `json:"description" db:"description"`             // Task template description
	Cadence        tasks.Cadence   `json:"cadence" db:"cadence"`                     // Task template cadence
	Category       tasks.Category  `json:"category" db:"category"`                   // Task template category
	CreatedAt      data.CustomTime `json:"created_at" db:"created_at"`               // Task record created at
	IsComplete     bool            `json:"is_complete" db:"is_complete"`             // Task record field
	CompletedAt    string          `json:"completed_at,omitempty" db:"completed_at"` // Task record field
	IsSatisfactory bool            `json:"is_satisfactory" db:"is_satisfactory"`     // Task record field
	IsProactive    bool            `json:"is_proactive" db:"is_proactive"`           // Task record field
	TaskSlug       string          `json:"task_slug,omitempty" db:"task_slug"`       // Task record slug
	IsArchived     bool            `json:"is_archived" db:"is_archived"`             // Task record field
	Username       string          `json:"username" db:"username"`                   // Allowance record field
	AllowanceSlug  string          `json:"allowance_slug" db:"allowance_slug"`       // Allowance record slug
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
