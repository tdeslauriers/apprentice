package tasks

import (
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/tasks"
)

// Service is an interface that aggregates all task services functionality
type Service interface {
	TaskService
	TaskErrorService
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql data.SqlRepository, i data.Indexer, c data.Cryptor) Service {
	return &service{
		TaskService:      NewTaskService(sql, i, c),
		TaskErrorService: NewTaskErrorService(),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface
type service struct {
	TaskService
	TaskErrorService
}

// Task is a struct that represents a task record in the database
type Task struct {
	Id             string          `db:"uuid"`
	CreatedAt      data.CustomTime `db:"created_at"`
	IsComplete     bool            `db:"is_complete"`
	CompletedAt    data.CustomTime `db:"completed_at"`
	IsSatisfactory bool            `db:"is_satisfactory"`
	IsProactive    bool            `db:"is_proactive"`
	Slug           string          `db:"slug"`
	IsArchived     bool            `db:"is_archived"`
}

// TaskAllowanceXref is a model that represents a many-to-many relationship
// between tasks and allowances in the db
type TaskAllowanceXref struct {
	// Id          int             `db:"id" json:"id,omitempty"`
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
	CompletedAt    data.CustomTime `json:"completed_at,omitempty" db:"completed_at"` // Task record field
	IsSatisfactory bool            `json:"is_satisfactory" db:"is_satisfactory"`     // Task record field
	IsProactive    bool            `json:"is_proactive" db:"is_proactive"`           // Task record field
	TaskSlug       string          `json:"task_slug,omitempty" db:"task_slug"`       // Task record slug
	IsArchived     bool            `json:"is_archived" db:"is_archived"`             // Task record field
	Username       string          `json:"username" db:"username"`                   // Allowance record field
	AllowanceSlug  string          `json:"allowance_slug" db:"allowance_slug"`       // Allowance record slug
}
