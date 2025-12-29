package templates

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/apprentice/internal/tasks"
	"github.com/tdeslauriers/apprentice/internal/util"
	"github.com/tdeslauriers/apprentice/pkg/api/allowances"
	api "github.com/tdeslauriers/apprentice/pkg/api/templates"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Service is an interface to handle template service functionality
type TemplateService interface {

	// GetTemplates retrieves all active template from the database including it's assignees.
	GetTemplates() ([]api.Template, error)

	// GetTemplate retrieves a template record from the database by slug including it's assignees.
	GetTemplate(slug string) (*api.Template, error)

	// CreateTemplate creates a new template record in the database
	CreateTemplate(ctx context.Context, cmd api.TemplateCmd) (*api.TemplateRecord, error)

	// UpdateTemplate updates a template record in the database
	UpdateTemplate(ctx context.Context, t *api.TemplateRecord) error

	// CreateAllowanceXref creates a new allowance-template xref record in the database
	CreateAllowanceXref(ctx context.Context, t *api.TemplateRecord, a *allowances.Allowance) (*AllowanceTemplateXref, error)

	// DeleteAllowanceXref deletes an allowance-template xref record from the database
	DeleteAllowanceXref(ctx context.Context, t *api.TemplateRecord, a *allowances.Allowance) error

	// CreateTaskXref creates a new task-template xref record in the database
	CreateTaskXref(ctx context.Context, t *api.TemplateRecord, ta *tasks.TaskRecord) (*TemplateTaskXref, error)
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewTemplateService(sql *sql.DB, c data.Cryptor) TemplateService {
	return &templateService{
		db:      NewTemplateRepository(sql),
		cryptor: c,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageTemplates)).
			With(slog.String(util.ComponentKey, util.ComponentTemplates)),
	}
}

var _ TemplateService = (*templateService)(nil)

// service is the concrete implementation of the Service interface
type templateService struct {
	db      TemplateRepository
	cryptor data.Cryptor // needed for decrypting allowance db record data in join queries

	logger *slog.Logger
}

// GetTemplates is a concrete implementation of the GetTemplates method in the TemplateService interface
// it retrieves all active task templates from the database including their assignees
func (s *templateService) GetTemplates() ([]api.Template, error) {

	// get all active templates (including assignee) from the database
	templates, err := s.db.FindActiveTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve all templates from db: %v", err)
	}

	// decrypt the allowance usernames
	// map of usernames so dont decrypt the same username multiple times
	uniqueEncrypted := make(map[string]*string, len(templates)*2)

	for _, t := range templates {
		// dumping into a map so can decrypt concurrently
		if _, ok := uniqueEncrypted[t.Username]; !ok {
			uniqueEncrypted[t.Username] = new(string)
		}
		if _, ok := uniqueEncrypted[t.AllowanceSlug]; !ok {
			uniqueEncrypted[t.AllowanceSlug] = new(string)
		}
	}

	// decrypt the usernames and slugs concurrently
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		errChan = make(chan error, len(uniqueEncrypted))
	)

	for encrypted := range uniqueEncrypted {

		wg.Add(1)
		go func(encrypted string, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			// errors in template creation can lead to empty assignees/slugs (xref not created)
			// need to check for empty strings and simply return them as empty
			if encrypted == "" {
				mu.Lock()
				*uniqueEncrypted[encrypted] = ""
				mu.Unlock()
				return
			}

			decrypted, err := s.cryptor.DecryptServiceData(encrypted)
			if err != nil {
				ch <- fmt.Errorf("%v", err)
				return
			}

			mu.Lock()
			*uniqueEncrypted[encrypted] = string(decrypted)
			mu.Unlock()
		}(encrypted, errChan, &wg)
	}

	wg.Wait()
	close(errChan)

	// check for any decryption errors
	if len(errChan) > 0 {
		errs := make([]error, 0, len(errChan))
		for err := range errChan {
			errs = append(errs, err)
		}
		return nil, fmt.Errorf("failed to decrypt %d username(s) and/or allowance slugs: %v",
			len(errs), errors.Join(errs...))
	}

	// consolidate to unique template records with usernames slices
	uniqueTemplates := make(map[string]api.Template, len(templates))
	for _, t := range templates {
		if _, ok := uniqueTemplates[t.Id]; !ok {
			uniqueTemplates[t.Id] = api.Template{
				Id:           t.Id,
				Name:         t.Name,
				Description:  t.Description,
				Cadence:      t.Cadence,
				Category:     t.Category,
				IsCalculated: t.IsCalculated,
				Slug:         t.TemplateSlug,
				CreatedAt:    t.CreatedAt,
				IsArchived:   t.IsArchived,
				Assignees:    make([]api.Assignee, 0),
			}
		}

		template := uniqueTemplates[t.Id]
		template.Assignees = append(template.Assignees, api.Assignee{
			Username:      *uniqueEncrypted[t.Username],
			AllowanceSlug: *uniqueEncrypted[t.AllowanceSlug],
		})
		uniqueTemplates[t.Id] = template
	}

	// convert map to slice
	result := make([]api.Template, 0, len(uniqueTemplates))
	for _, t := range uniqueTemplates {
		result = append(result, t)
	}

	s.logger.Info(fmt.Sprintf("successfully retrieved %d template records", len(result)))

	return result, nil
}

// GetTemplate is a concrete implementation of the GetTemplate method in the TemplateService interface
func (s *templateService) GetTemplate(slug string) (*api.Template, error) {

	// validate slug
	// redundant check, but good practice
	if !validate.IsValidUuid(slug) {
		return nil, fmt.Errorf("invalid template slug: %s", slug)
	}

	// look up the template record by slug
	templateAssignees, err := s.db.FindTemplateAssignees(slug)
	if err != nil {
		return nil, err
	}

	// decrypt the allowance usernames
	var (
		wg      sync.WaitGroup
		errChan = make(chan error, len(templateAssignees))
	)

	for i := range templateAssignees {
		wg.Add(1)
		go func(index int, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			// decrypt username
			username, err := s.cryptor.DecryptServiceData(templateAssignees[index].Username)
			if err != nil {
				ch <- fmt.Errorf("%v", err)
				return
			}
			templateAssignees[index].Username = string(username)

			// decrypt allowance slug
			slug, err := s.cryptor.DecryptServiceData(templateAssignees[index].AllowanceSlug)
			if err != nil {
				ch <- fmt.Errorf("%v", err)
				return
			}
			templateAssignees[index].AllowanceSlug = string(slug)

		}(i, errChan, &wg)
	}

	wg.Wait()
	close(errChan)

	// check for any decryption errors
	if len(errChan) > 0 {
		errs := make([]error, 0, len(errChan))
		for err := range errChan {
			errs = append(errs, err)
		}
		return nil, fmt.Errorf("failed to decrypt %d username(s): %v", len(errs), errors.Join(errs...))
	}

	// consolidate to unique template record with usernames slice
	uniqueTemplate := api.Template{
		Id:           templateAssignees[0].Id,
		Name:         templateAssignees[0].Name,
		Description:  templateAssignees[0].Description,
		Cadence:      templateAssignees[0].Cadence,
		Category:     templateAssignees[0].Category,
		IsCalculated: templateAssignees[0].IsCalculated,
		Slug:         templateAssignees[0].TemplateSlug,
		CreatedAt:    templateAssignees[0].CreatedAt,
		IsArchived:   templateAssignees[0].IsArchived,
		Assignees:    make([]api.Assignee, 0),
	}
	for _, t := range templateAssignees {

		uniqueTemplate.Assignees = append(uniqueTemplate.Assignees, api.Assignee{
			Username:      t.Username,
			AllowanceSlug: t.AllowanceSlug,
		})
	}

	s.logger.Info(fmt.Sprintf("successfully retrieved template record for slug %s", slug))

	return &uniqueTemplate, nil
}

// CreateTemplate is a concrete implementation of the CreateTemplate method in the TemplateService interface
func (s *templateService) CreateTemplate(ctx context.Context, cmd api.TemplateCmd) (*api.TemplateRecord, error) {

	// add telemetry fields to logger if exists in context
	log := s.logger
	if telemetry, ok := connect.GetTelemetryFromContext(ctx); ok && telemetry != nil {
		log = log.With(telemetry.TelemetryFields()...)
	} else {
		log.Warn("no telemetry found in context for CreateTemplate")
	}

	// validate the command
	// redundant check, but good practice
	if err := cmd.ValidateCmd(); err != nil {
		return nil, fmt.Errorf("invalid template create-command: %v", err)
	}

	// generate UUIDs for the template id and slug
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID for template id: %v", err)
	}

	slug, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID for template slug: %v", err)
	}

	// create the new template record
	t := api.TemplateRecord{
		Id:          id.String(),
		Name:        cmd.Name,
		Description: cmd.Description,
		Cadence:     cmd.Cadence,
		Category:    cmd.Category,
		Slug:        slug.String(),
		CreatedAt:   data.CustomTime{Time: time.Now().UTC()},
		IsArchived:  false,
	}

	if err := s.db.InsertTemplate(t); err != nil {
		return nil, fmt.Errorf("failed to insert template record in to db: %v", err)
	}

	log.Info(fmt.Sprintf("successfully created template record %s in database", t.Id))

	return &t, nil
}

// UpdateTemplate is a concrete implementation of the UpdateTemplate method in the TemplateService interface
func (s *templateService) UpdateTemplate(ctx context.Context, t *api.TemplateRecord) error {

	// add telemetry fields to logger if exists in context
	log := s.logger
	if telemetry, ok := connect.GetTelemetryFromContext(ctx); ok && telemetry != nil {
		log = log.With(telemetry.TelemetryFields()...)
	} else {
		s.logger.Warn("no telemetry found in context for UpdateTemplate")
	}

	// validate the template record
	// redundant check, but good practice
	if err := t.Validate(); err != nil {
		return fmt.Errorf("invalid template record: %v", err)
	}

	// update the template record in the database
	if err := s.db.UpdateTemplate(*t); err != nil {
		return fmt.Errorf("failed to update template record in db: %v", err)
	}

	log.Info(fmt.Sprintf("successfully updated template record %s in database", t.Id))

	return nil
}

// CreateAllowanceXref is a concrete implementation of the CreateAllowanceXref method in the TemplateService interface
func (s *templateService) CreateAllowanceXref(
	ctx context.Context,
	t *api.TemplateRecord,
	a *allowances.Allowance,
) (*AllowanceTemplateXref, error) {

	log := s.logger
	// add telemetry fields to logger if exists in context
	if telemetry, ok := connect.GetTelemetryFromContext(ctx); ok && telemetry != nil {
		log = log.With(telemetry.TelemetryFields()...)
	} else {
		log.Warn("no telemetry found in context for CreateAllowanceXref")
	}

	// create the new xref record
	xref := AllowanceTemplateXref{
		TemplateId:  t.Id,
		AllowanceId: a.Id,
		CreatedAt:   data.CustomTime{Time: time.Now().UTC()},
	}

	if err := s.db.InsertTemplateAllowanceXref(xref); err != nil {
		return nil, fmt.Errorf("failed to insert allowance-template xref record in to db: %v", err)
	}

	log.Info(fmt.Sprintf("successfully created xref record between allowance %s and template %s", a.Username, t.Name))

	return &xref, nil
}

// DeleteAllowanceXref is a concrete implementation of the DeleteAllowanceXref method in the TemplateService interface
func (s *templateService) DeleteAllowanceXref(ctx context.Context, t *api.TemplateRecord, a *allowances.Allowance) error {

	// add telemetry fields to logger if exists in context
	log := s.logger
	if telemetry, ok := connect.GetTelemetryFromContext(ctx); ok && telemetry != nil {
		log = log.With(telemetry.TelemetryFields()...)
	} else {
		s.logger.Warn("no telemetry found in context for DeleteAllowanceXref")
	}

	// delete the xref record from the database
	if err := s.db.DeleteTemplateAllowanceXref(t.Id, a.Id); err != nil {
		return fmt.Errorf("failed to delete allowance-template xref record from db: %v", err)
	}

	log.Info(fmt.Sprintf("successfully deleted xref record between allowance %s and template %s", a.Username, t.Name))

	return nil
}

// CreateTaskXref is a concrete implementation of the CreateTaskXref method in the TemplateService interface
func (s *templateService) CreateTaskXref(
	ctx context.Context,
	t *api.TemplateRecord,
	ta *tasks.TaskRecord,
) (*TemplateTaskXref, error) {

	// add telemetry fields to logger if exists in context
	log := s.logger
	if telemetry, ok := connect.GetTelemetryFromContext(ctx); ok && telemetry != nil {
		log = log.With(telemetry.TelemetryFields()...)
	} else {
		log.Warn("no telemetry found in context for CreateTaskXref")
	}

	// create the new xref record
	xref := TemplateTaskXref{
		TemplateId: t.Id,
		TaskId:     ta.Id,
		CreatedAt:  data.CustomTime{Time: time.Now().UTC()},
	}

	if err := s.db.InsertTemplateTaskXref(xref); err != nil {
		return nil, fmt.Errorf("failed to insert template-task xref record in to db: %v", err)
	}

	log.Info(fmt.Sprintf("successfully created xref record between template %s and task %s", t.Name, ta.Slug))

	return &xref, nil
}
