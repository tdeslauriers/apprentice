package templates

import (
	"apprentice/internal/util"
	"apprentice/pkg/tasks"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	exotasks "github.com/tdeslauriers/carapace/pkg/tasks"
)

// Service is an interface to handle template service functionality
type TemplateService interface {

	// CreateTemplate creates a new template record in the database
	CreateTemplate(cmd exotasks.TemplateCmd) (*Template, error)

	// CreateAllowanceXref creates a new allowance-template xref record in the database
	CreateAllowanceXref(t *Template, a *exotasks.Allowance) (*AllowanceTemplateXref, error)

	// CreateTaskXref creates a new task-template xref record in the database
	CreateTaskXref(t *Template, ta *tasks.Task) (*TemplateTaskXref, error)
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewTemplateService(sql data.SqlRepository) TemplateService {
	return &templateService{
		db: sql,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageTemplates)).
			With(slog.String(util.ComponentKey, util.ComponentTemplates)),
	}
}

var _ TemplateService = (*templateService)(nil)

// service is the concrete implementation of the Service interface
type templateService struct {
	db data.SqlRepository

	logger *slog.Logger
}

// CreateTemplate is a concrete implementation of the CreateTemplate method in the TemplateService interface
func (s *templateService) CreateTemplate(cmd exotasks.TemplateCmd) (*Template, error) {

	// validate the command
	// redundant check, but good practice
	if err := cmd.ValidateCmd(); err != nil {
		errMsg := fmt.Sprintf("invalid template create-command: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	// generate UUIDs for the template id and slug
	id, err := uuid.NewRandom()
	if err != nil {
		errMsg := fmt.Sprintf("failed to generate UUID for template id: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	slug, err := uuid.NewRandom()
	if err != nil {
		errMsg := fmt.Sprintf("failed to generate UUID for template slug: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	// create the new template record
	t := &Template{
		Id:          id.String(),
		Name:        cmd.Name,
		Description: cmd.Description,
		Cadence:     cmd.Cadence,
		Category:    cmd.Category,
		Slug:        slug.String(),
		CreatedAt:   data.CustomTime{Time: time.Now().UTC()},
		IsArchived:  false,
	}

	qry := `INSERT INTO templates (uuid, name, description, cadence, category, slug, created_at, is_archived)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, t); err != nil {
		errMsg := fmt.Sprintf("failed to insert template record in to db: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	s.logger.Info(fmt.Sprintf("created new template record: %v", t))

	return t, nil
}

// CreateAllowanceXref is a concrete implementation of the CreateAllowanceXref method in the TemplateService interface
func (s *templateService) CreateAllowanceXref(t *Template, a *exotasks.Allowance) (*AllowanceTemplateXref, error) {

	// create the new xref record
	xref := &AllowanceTemplateXref{
		TemplateId:  t.Id,
		AllowanceId: a.Id,
		CreatedAt:   data.CustomTime{Time: time.Now().UTC()},
	}

	qry := `INSERT INTO allowance_template ( template_uuid, allowance_uuid, created_at)
			VALUES (?, ?, ?)`
	if err := s.db.InsertRecord(qry, xref); err != nil {
		errMsg := fmt.Sprintf("failed to insert allowance-template xref record in to db: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	s.logger.Info(fmt.Sprintf("successfully created xref record between allowance %s and template %s", a.Username, t.Name))

	return xref, nil
}

// CreateTaskXref is a concrete implementation of the CreateTaskXref method in the TemplateService interface
func (s *templateService) CreateTaskXref(t *Template, ta *tasks.Task) (*TemplateTaskXref, error) {

	// create the new xref record
	xref := &TemplateTaskXref{
		TemplateId: t.Id,
		TaskId:     ta.Id,
		CreatedAt:  data.CustomTime{Time: time.Now().UTC()},
	}

	qry := `INSERT INTO template_task ( template_uuid, task_uuid, created_at)
			VALUES (?, ?, ?)`
	if err := s.db.InsertRecord(qry, xref); err != nil {
		errMsg := fmt.Sprintf("failed to insert template-task xref record in to db: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	s.logger.Info(fmt.Sprintf("successfully created xref record between template %s and task %s", t.Name, ta.Slug))

	return xref, nil
}
