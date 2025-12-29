package templates

import (
	"database/sql"

	"github.com/tdeslauriers/apprentice/pkg/api/tasks"
	"github.com/tdeslauriers/carapace/pkg/data"
)

// Service is an interface that aggregates all template services functionality
type Service interface {
	TemplateService
	TemplateErrorService
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql *sql.DB, c data.Cryptor) Service {
	return &service{
		TemplateService:      NewTemplateService(sql, c),
		TemplateErrorService: NewTemplateErrorService(),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface
type service struct {
	TemplateService
	TemplateErrorService
}

// TemplateAssignee is a struct that represents a template + allowance db join query row result
type TemplateAssignee struct {
	Id            string          `db:"uuid"`
	Name          string          `db:"name"`
	Description   string          `db:"description"`
	Cadence       tasks.Cadence   `db:"cadence"`
	Category      tasks.Category  `db:"category"`
	IsCalculated  bool            `db:"is_calculated"`
	TemplateSlug  string          `db:"template_slug"`
	CreatedAt     data.CustomTime `db:"created_at"`
	IsArchived    bool            `db:"is_archived"`
	Username      string          `db:"username"`
	AllowanceSlug string          `db:"allowance_slug"`
}

// AllowanceTemplateXref is a model that represents a many-to-many relationship
// between allowances and templates in the db
type AllowanceTemplateXref struct {
	Id          int             `db:"id" json:"id,omitempty"`
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
