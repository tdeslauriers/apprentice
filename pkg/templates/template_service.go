package templates

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/tdeslauriers/apprentice/internal/util"

	"github.com/tdeslauriers/apprentice/pkg/allowances"
	"github.com/tdeslauriers/apprentice/pkg/tasks"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Service is an interface to handle template service functionality
type TemplateService interface {

	// GetTemplates retrieves all active template from the database including it's assignees.
	GetTemplates() ([]Template, error)

	// GetTemplate retrieves a template record from the database by slug including it's assignees.
	GetTemplate(slug string) (*Template, error)

	// CreateTemplate creates a new template record in the database
	CreateTemplate(ctx context.Context, cmd TemplateCmd) (*TemplateRecord, error)

	// UpdateTemplate updates a template record in the database
	UpdateTemplate(ctx context.Context, t *TemplateRecord) error

	// CreateAllowanceXref creates a new allowance-template xref record in the database
	CreateAllowanceXref(ctx context.Context, t *TemplateRecord, a *allowances.Allowance) (*AllowanceTemplateXref, error)

	// DeleteAllowanceXref deletes an allowance-template xref record from the database
	DeleteAllowanceXref(ctx context.Context, t *TemplateRecord, a *allowances.Allowance) error

	// CreateTaskXref creates a new task-template xref record in the database
	CreateTaskXref(ctx context.Context, t *TemplateRecord, ta *tasks.TaskRecord) (*TemplateTaskXref, error)
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewTemplateService(sql data.SqlRepository, c data.Cryptor) TemplateService {
	return &templateService{
		db:      sql,
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
	db      data.SqlRepository
	cryptor data.Cryptor // needed for decrypting allowance db record data in join queries

	logger *slog.Logger
}

// GetTemplates is a concrete implementation of the GetTemplates method in the TemplateService interface
// it retrieves all active task templates from the database including their assignees
func (s *templateService) GetTemplates() ([]Template, error) {

	qry := `
		SELECT 
			t.uuid, 
			t.name, 
			t.description, 
			t.cadence, 
			t.category, 
			t.is_calculated,
			t.slug AS template_slug, 
			t.created_at, 
			t.is_archived,
			a.username,
			a.slug AS allowance_slug
		FROM template t 
			LEFT OUTER JOIN template_allowance ta ON t.uuid = ta.template_uuid
			LEFT OUTER JOIN allowance a ON ta.allowance_uuid = a.uuid
		WHERE t.is_archived = FALSE`
	var templates []TemplateAssignee
	if err := s.db.SelectRecords(qry, &templates); err != nil {
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
	uniqueTemplates := make(map[string]Template, len(templates))
	for _, t := range templates {
		if _, ok := uniqueTemplates[t.Id]; !ok {
			uniqueTemplates[t.Id] = Template{
				Id:           t.Id,
				Name:         t.Name,
				Description:  t.Description,
				Cadence:      t.Cadence,
				Category:     t.Category,
				IsCalculated: t.IsCalculated,
				Slug:         t.TemplateSlug,
				CreatedAt:    t.CreatedAt,
				IsArchived:   t.IsArchived,
				Assignees:    make([]Assignee, 0),
			}
		}

		template := uniqueTemplates[t.Id]
		template.Assignees = append(template.Assignees, Assignee{
			Username:      *uniqueEncrypted[t.Username],
			AllowanceSlug: *uniqueEncrypted[t.AllowanceSlug],
		})
		uniqueTemplates[t.Id] = template
	}

	// convert map to slice
	result := make([]Template, 0, len(uniqueTemplates))
	for _, t := range uniqueTemplates {
		result = append(result, t)
	}

	s.logger.Info(fmt.Sprintf("successfully retrieved %d template records", len(result)))

	return result, nil
}

// GetTemplate is a concrete implementation of the GetTemplate method in the TemplateService interface
func (s *templateService) GetTemplate(slug string) (*Template, error) {

	// validate slug
	// redundant check, but good practice
	if !validate.IsValidUuid(slug) {
		return nil, fmt.Errorf("invalid template slug: %s", slug)
	}

	// look up the template record by slug
	qry := `
	SELECT 
		t.uuid, 
		t.name, 
		t.description, 
		t.cadence, 
		t.category, 
		t.is_calculated,
		t.slug AS template_slug, 
		t.created_at, 
		t.is_archived,
		a.username,
		a.slug AS allowance_slug
	FROM template t 
		LEFT OUTER JOIN template_allowance ta ON t.uuid = ta.template_uuid
		LEFT OUTER JOIN allowance a ON ta.allowance_uuid = a.uuid
		WHERE t.slug = ?`
	// need to look up as slice because of join/more than one user could be assigned
	var templates []TemplateAssignee
	if err := s.db.SelectRecords(qry, &templates, slug); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("template record not found for slug: %s", slug)
		}
		return nil, fmt.Errorf("failed to retrieve template record from db: %v", err)
	}

	// decrypt the allowance usernames
	var (
		wg      sync.WaitGroup
		errChan = make(chan error, len(templates))
	)

	for i := range templates {
		wg.Add(1)
		go func(index int, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			// decrypt username
			username, err := s.cryptor.DecryptServiceData(templates[index].Username)
			if err != nil {
				ch <- fmt.Errorf("%v", err)
				return
			}
			templates[index].Username = string(username)

			// decrypt allowance slug
			slug, err := s.cryptor.DecryptServiceData(templates[index].AllowanceSlug)
			if err != nil {
				ch <- fmt.Errorf("%v", err)
				return
			}
			templates[index].AllowanceSlug = string(slug)

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
	uniqueTemplate := Template{
		Id:           templates[0].Id,
		Name:         templates[0].Name,
		Description:  templates[0].Description,
		Cadence:      templates[0].Cadence,
		Category:     templates[0].Category,
		IsCalculated: templates[0].IsCalculated,
		Slug:         templates[0].TemplateSlug,
		CreatedAt:    templates[0].CreatedAt,
		IsArchived:   templates[0].IsArchived,
		Assignees:    make([]Assignee, 0),
	}
	for _, t := range templates {

		uniqueTemplate.Assignees = append(uniqueTemplate.Assignees, Assignee{
			Username:      t.Username,
			AllowanceSlug: t.AllowanceSlug,
		})
	}

	s.logger.Info(fmt.Sprintf("successfully retrieved template record for slug %s", slug))

	return &uniqueTemplate, nil
}

// CreateTemplate is a concrete implementation of the CreateTemplate method in the TemplateService interface
func (s *templateService) CreateTemplate(ctx context.Context, cmd TemplateCmd) (*TemplateRecord, error) {

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
	t := TemplateRecord{
		Id:          id.String(),
		Name:        cmd.Name,
		Description: cmd.Description,
		Cadence:     cmd.Cadence,
		Category:    cmd.Category,
		Slug:        slug.String(),
		CreatedAt:   data.CustomTime{Time: time.Now().UTC()},
		IsArchived:  false,
	}

	qry := `INSERT INTO template (uuid, name, description, cadence, category, is_calculated, slug, created_at, is_archived)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, t); err != nil {
		return nil, fmt.Errorf("failed to insert template record in to db: %v", err)
	}

	log.Info(fmt.Sprintf("successfully created template record %s in database", t.Id))

	return &t, nil
}

// UpdateTemplate is a concrete implementation of the UpdateTemplate method in the TemplateService interface
func (s *templateService) UpdateTemplate(ctx context.Context, t *TemplateRecord) error {

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
	qry := `UPDATE template
			SET name = ?, 
				description = ?, 
				cadence = ?, 
				category = ?, 
				is_calculated = ?, 
				is_archived = ?
			WHERE uuid = ?`
	if err := s.db.UpdateRecord(qry, t.Name, t.Description, t.Cadence, t.Category, t.IsCalculated, t.IsArchived, t.Id); err != nil {
		return fmt.Errorf("failed to update template record in db: %v", err)
	}

	log.Info(fmt.Sprintf("successfully updated template record %s in database", t.Id))

	return nil
}

// CreateAllowanceXref is a concrete implementation of the CreateAllowanceXref method in the TemplateService interface
func (s *templateService) CreateAllowanceXref(
	ctx context.Context,
	t *TemplateRecord,
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

	qry := `INSERT INTO template_allowance ( template_uuid, allowance_uuid, created_at)
			VALUES (?, ?, ?)`
	if err := s.db.InsertRecord(qry, xref); err != nil {
		return nil, fmt.Errorf("failed to insert allowance-template xref record in to db: %v", err)
	}

	log.Info(fmt.Sprintf("successfully created xref record between allowance %s and template %s", a.Username, t.Name))

	return &xref, nil
}

// DeleteAllowanceXref is a concrete implementation of the DeleteAllowanceXref method in the TemplateService interface
func (s *templateService) DeleteAllowanceXref(ctx context.Context, t *TemplateRecord, a *allowances.Allowance) error {

	// add telemetry fields to logger if exists in context
	log := s.logger
	if telemetry, ok := connect.GetTelemetryFromContext(ctx); ok && telemetry != nil {
		log = log.With(telemetry.TelemetryFields()...)
	} else {
		s.logger.Warn("no telemetry found in context for DeleteAllowanceXref")
	}

	// delete the xref record from the database
	qry := `DELETE FROM template_allowance 
			WHERE template_uuid = ? AND allowance_uuid = ?`
	if err := s.db.DeleteRecord(qry, t.Id, a.Id); err != nil {
		return fmt.Errorf("failed to delete allowance-template xref record from db: %v", err)
	}

	log.Info(fmt.Sprintf("successfully deleted xref record between allowance %s and template %s", a.Username, t.Name))

	return nil
}

// CreateTaskXref is a concrete implementation of the CreateTaskXref method in the TemplateService interface
func (s *templateService) CreateTaskXref(ctx context.Context, t *TemplateRecord, ta *tasks.TaskRecord) (*TemplateTaskXref, error) {

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

	qry := `INSERT INTO template_task ( template_uuid, task_uuid, created_at)
			VALUES (?, ?, ?)`
	if err := s.db.InsertRecord(qry, xref); err != nil {
		return nil, fmt.Errorf("failed to insert template-task xref record in to db: %v", err)
	}

	log.Info(fmt.Sprintf("successfully created xref record between template %s and task %s", t.Name, ta.Slug))

	return &xref, nil
}
