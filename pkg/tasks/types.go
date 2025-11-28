package tasks

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
	"github.com/tdeslauriers/shaw/pkg/user"
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

// cadence is a type that represents the cadence of a task template's recurrence.
type Cadence string

// possible cadence values => for unmarrshalling json validation
const (
	Adhoc     Cadence = "ADHOC"
	Daily     Cadence = "DAILY"
	Weekly    Cadence = "WEEKLY"
	Monthly   Cadence = "MONTHLY"
	Quarterly Cadence = "QUARTERLY"
	Anually   Cadence = "ANNUALLY"
)

// customr unmarshaler for cadence type so that it errors on invalid values
func (c *Cadence) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	switch s {
	case string(Adhoc), string(Daily), string(Weekly), string(Monthly), string(Quarterly), string(Anually):
		*c = Cadence(s)
		return nil
	default:
		return fmt.Errorf("invalid cadence: %q", s)
	}
}

// IsValidCadence checks if a cadence is valid
// redundant if the custom unmarshaler is used on a json payload, but that isnt guaranteed.
func (c *Cadence) IsValidCadence() error {
	switch *c {
	case Adhoc, Daily, Weekly, Monthly, Quarterly, Anually:
		return nil
	default:
		return fmt.Errorf("invalid cadence: %q", *c)
	}
}

// Category is a type that represents the category of a task template, such as "work" or "home".
type Category string

const (
	Bills  Category = "BILLS"
	Car    Category = "CAR"
	Dev    Category = "DEV"
	Health Category = "HEALTH"
	House  Category = "HOUSE"
	Kids   Category = "KIDS"
	Pets   Category = "PETS"
	Sports Category = "SPORTS"
	Study  Category = "STUDY"
	Work   Category = "WORK"
	Yard   Category = "YARD"
	Other  Category = "OTHER"
)

// UnmarshalJSON is a custom unmarshaler for the Category type so that it errors on invalid values.
func (c *Category) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	switch s {
	case string(Bills), string(Car), string(Dev), string(Health), string(House), string(Kids),
		string(Pets), string(Sports), string(Study), string(Work), string(Yard), string(Other):
		*c = Category(s)
		return nil
	default:
		return fmt.Errorf("invalid category: %q", s)
	}
}

// IsValidCategory checks if a category is valid
// redundant if the custom unmarshaler is used on a json payload, but that isnt guaranteed.
func (c *Category) IsValidCategory() error {
	switch *c {
	case Bills, Car, Dev, Health, House, Kids, Pets, Sports, Study, Work, Yard, Other:
		return nil
	default:
		return fmt.Errorf("invalid category: %q", *c)
	}
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

// Task is a model that represents a task as in json
// It is a composite object of fields from task and task template models.
// It also includes a slice of assignees.
type Task struct {
	Id             string          `json:"id,omitempty"`           // Tasks record uuid
	Name           string          `json:"name"`                   // Task template name
	Description    string          `json:"description"`            // Task template description
	Cadence        Cadence         `json:"cadence"`                // Task template cadence
	Category       Category        `json:"category"`               // Task template category
	CreatedAt      data.CustomTime `json:"created_at"`             // Task record created at
	IsComplete     bool            `json:"is_complete"`            // Task record field
	CompletedAt    string          `json:"completed_at,omitempty"` // Task record field
	IsSatisfactory bool            `json:"is_satisfactory"`        // Task record field
	IsProactive    bool            `json:"is_proactive"`           // Task record field
	TaskSlug       string          `json:"task_slug,omitempty"`    // Task record slug
	IsArchived     bool            `json:"is_archived"`            // Task record field
	AllowanceSlug  string          `json:"allowance_slug"`         // Task record allowance slug
	Assignee       user.User       `json:"assignee"`               // Task assignee via xref (only one person per task record)
}

// TaskRecord is a struct that represents a task-template join/composite record in the database
type TaskData struct {
	Id             string          `json:"id,omitempty" db:"uuid"`                   // Tasks record uuid
	Name           string          `json:"name" db:"name"`                           // Task template name
	Description    string          `json:"description" db:"description"`             // Task template description
	Cadence        Cadence         `json:"cadence" db:"cadence"`                     // Task template cadence
	Category       Category        `json:"category" db:"category"`                   // Task template category
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

// TaskStatusCmd is a model for updating the status of a task
// recieved by the gateway service.
type TaskStatusCmd struct {
	Csrf     string `json:"csrf,omitempty"`
	TaskSlug string `json:"task_slug"`
	Status   string `json:"status"`
}

// ValidateCmd validates the TaskStatusCmd struct
// Note: it does not include any business logic validation, only data validation.
func (t *TaskStatusCmd) ValidateCmd() error {
	// csrf
	if t.Csrf != "" {
		if !validate.IsValidUuid(t.Csrf) {
			return fmt.Errorf("invalid csrf token submitted with request")
		}
	}

	// task slug
	if t.TaskSlug != "" {
		if !validate.IsValidUuid(t.TaskSlug) {
			return fmt.Errorf("invalid task slug")
		}
	}

	// status
	if len(t.Status) <= 0 {
		return fmt.Errorf("status is a required field")
	}

	t.Status = strings.ToLower(strings.TrimSpace(t.Status))

	switch t.Status {
	case "is_complete", "is_satisfactory", "is_proactive", "is_archived":
	default:
		return fmt.Errorf("invalid status: %s", t.Status)
	}

	return nil
}
