package templates

import (
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/tasks"
)

// Service is an interface that aggregates all template services functionality
type Service interface {
	TemplateService
	TemplateErrorService
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql data.SqlRepository) Service {
	return &service{
		TemplateService:      NewTemplateService(sql),
		TemplateErrorService: NewTemplateErrorService(),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface
type service struct {
	TemplateService
	TemplateErrorService
}

// Template is a struct that represents a template record in the database
type Template struct {
	Id          string          `db:"uuid"`
	Name        string          `db:"name"`
	Description string          `db:"description"`
	Cadence     tasks.Cadence   `db:"cadence"`
	Category    tasks.Category  `db:"category"`
	Slug        string          `db:"slug"`
	CreatedAt   data.CustomTime `db:"created_at"`
	IsArchived  bool            `db:"is_archived"`
}

// AllowanceTemplateXref is a model that represents a many-to-many relationship
// between allowances and templates in the db
type AllowanceTemplateXref struct {
	// Id          int             `db:"id" json:"id,omitempty"`
	TemplateId  string          `db:"template_uuid" json:"template_uuid,omitempty"`
	AllowanceId string          `db:"allowance_uuid" json:"allowance_uuid,omitempty"`
	CreatedAt   data.CustomTime `db:"created_at" json:"created_at,omitempty"`
}

// TemplateTaskXref is a model that represents a many-to-many relationship
// between templates and tasks in the db
type TemplateTaskXref struct {
	// Id          int             `db:"id" json:"id,omitempty"`
	TemplateId string          `db:"template_uuid" json:"template_uuid,omitempty"`
	TaskId     string          `db:"task_uuid" json:"task_uuid,omitempty"`
	CreatedAt  data.CustomTime `db:"created_at" json:"created_at,omitempty"`
}
