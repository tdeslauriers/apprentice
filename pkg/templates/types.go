package templates

import (
	"fmt"
	"strings"

	"github.com/tdeslauriers/apprentice/pkg/tasks"
	"github.com/tdeslauriers/carapace/pkg/data"
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

// TaskTemplate is a struct for a json model meant to update/insert task templates.
// It is not a database model and is a subset of the db record fields.
type TemplateCmd struct {
	Csrf string `json:"csrf,omitempty"`

	Name         string         `json:"name"`
	Description  string         `json:"description"`
	Cadence      tasks.Cadence  `json:"cadence"`
	Category     tasks.Category `json:"category"`
	IsCalculated bool           `json:"is_calculated"`
	IsArchived   bool           `json:"is_archived"`

	Assignees []string `json:"assignees"` // email addresses/usernames
}

// ValidateCmd validates the TemplateCmd struct
// Note: it does not include any business logic validation, only data validation.
func (t *TemplateCmd) ValidateCmd() error {

	// csrf
	if t.Csrf != "" {
		if !validate.IsValidUuid(t.Csrf) {
			return fmt.Errorf("invalid csrf token submitted with request")
		}
	}

	// name
	if len(strings.TrimSpace(t.Name)) < 2 || len(strings.TrimSpace(t.Name)) > 64 {
		return fmt.Errorf("name is a required field and must be between 2 and 64 characters in length")
	}

	// description
	if len(strings.TrimSpace(t.Description)) < 2 || len(strings.TrimSpace(t.Description)) > 255 {
		return fmt.Errorf("description is a required field and must be between 2 and 255 characters in length")
	}

	// cadence
	if len(t.Cadence) == 0 {
		return fmt.Errorf("cadence is a required field")
	}

	if err := t.Cadence.IsValidCadence(); err != nil {
		return err
	}

	// category
	if len(t.Category) == 0 {
		return fmt.Errorf("category is a required field")
	}

	if err := t.Category.IsValidCategory(); err != nil {
		return err
	}

	// assignees
	if len(t.Assignees) == 0 {
		return fmt.Errorf("assignees is a required field")
	}

	for _, a := range t.Assignees {
		if err := validate.IsValidEmail(a); err != nil {
			return fmt.Errorf("invalid assignee: %v", err)
		}
	}

	return nil
}

// Template is a struct that represents a task template as in json
// not it includes a slice of assignees, which is not in the db model.
type Template struct {
	Id           string          `json:"id,omitempty"`
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Cadence      tasks.Cadence   `json:"cadence"`
	Category     tasks.Category  `json:"category"`
	IsCalculated bool            `json:"is_calculated"`
	Slug         string          `json:"slug,omitempty"`
	CreatedAt    data.CustomTime `json:"created_at"`
	IsArchived   bool            `json:"is_archived"`
	Assignees    []Assignee      `json:"assignees"`
}

// Assignee is a model that is a composite of the profile.User model and the Allowance model.
// It is used to represent a user that is assigned to a task template.
type Assignee struct {
	Username      string `json:"username,omitempty"`  // email address
	Firstname     string `json:"firstname,omitempty"` // first name
	Lastname      string `json:"lastname,omitempty"`  // last name
	AllowanceSlug string `json:"allowance_slug"`      // allowance slug
}

// TemplateRecord is a struct that represents a template record in the database
type TemplateRecord struct {
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
func (t *TemplateRecord) Validate() error {

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
