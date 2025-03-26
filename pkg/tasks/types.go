package tasks

import "github.com/tdeslauriers/carapace/pkg/data"

// Service is an interface that aggregates all task services functionality
type Service interface {
	TaskService
	TaskErrorService
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql data.SqlRepository) Service {
	return &service{
		TaskService:      NewTaskService(sql),
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
