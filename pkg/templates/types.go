package templates

import (
	"fmt"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/tasks"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Service is an interface that aggregates all template services functionality
type Service interface {
	TemplateService
	TemplateErrorService
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql data.SqlRepository, c data.Cryptor) Service {
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

// Template is a struct that represents a template record in the database
type Template struct {
	Id           string          `db:"uuid" json:"uuid,omitempty"`
	Name         string          `db:"name" json:"name"`
	Description  string          `db:"description" json:"description"`
	Cadence      tasks.Cadence   `db:"cadence" json:"cadence"`
	Category     tasks.Category  `db:"category" json:"category"`
	IsCalculated bool            `db:"is_calculated" json:"is_calculated"`
	Slug         string          `db:"slug" json:"slug"`
	CreatedAt    data.CustomTime `db:"created_at" json:"created_at"`
	IsArchived   bool            `db:"is_archived" json:"is_archived"`
}

// Validate checks the template struct for valid values
func (t *Template) Validate() error {

	// uuid
	if !validate.IsValidUuid(t.Id) {
		return fmt.Errorf("invalid template id")
	}

	// name
	if len(t.Name) < 2 || len(t.Name) > 64 {
		return fmt.Errorf("invalid template name, must be between 2 and 64 characters")
	}

	// description
	if len(t.Description) < 2 || len(t.Description) > 255 {
		return fmt.Errorf("invalid template description, must be between 2 and 255 characters")
	}

	// cadence
	if err := t.Cadence.IsValidCadence(); err != nil {
		return err
	}

	// category
	if err := t.Category.IsValidCategory(); err != nil {
		return err
	}

	// slug
	if !validate.IsValidUuid(t.Slug) {
		return fmt.Errorf("invalid template slug")
	}

	// created_at will not be updated ever so no need to validate

	return nil
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
