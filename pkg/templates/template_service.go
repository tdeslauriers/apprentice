package templates

import (
	"apprentice/internal/util"
	"apprentice/pkg/tasks"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/profile"
	exotasks "github.com/tdeslauriers/carapace/pkg/tasks"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Service is an interface to handle template service functionality
type TemplateService interface {

	// GetTemplates retrieves a template record from the database including it's assignees.
	GetTemplates() ([]exotasks.Template, error)

	// GetTemplate retrieves a template record from the database by slug including it's assignees.
	GetTemplate(slug string) (*exotasks.Template, error)

	// CreateTemplate creates a new template record in the database
	CreateTemplate(cmd exotasks.TemplateCmd) (*Template, error)

	// UpdateTemplate updates a template record in the database
	UpdateTemplate(t *Template) error

	// CreateAllowanceXref creates a new allowance-template xref record in the database
	CreateAllowanceXref(t *Template, a *exotasks.Allowance) (*AllowanceTemplateXref, error)

	// DeleteAllowanceXref deletes an allowance-template xref record from the database
	DeleteAllowanceXref(t *Template, a *exotasks.Allowance) error

	// CreateTaskXref creates a new task-template xref record in the database
	CreateTaskXref(t *Template, ta *tasks.Task) (*TemplateTaskXref, error)
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
func (s *templateService) GetTemplates() ([]exotasks.Template, error) {

	qry := `
		SELECT 
			t.uuid, 
			t.name, 
			t.description, 
			t.cadence, 
			t.category, 
			t.slug, 
			t.created_at, 
			t.is_archived,
			a.username
		FROM template t 
			LEFT OUTER JOIN template_allowance ta ON t.uuid = ta.template_uuid
			LEFT OUTER JOIN allowance a ON ta.allowance_uuid = a.uuid`
	var templates []TemplateAssignee
	if err := s.db.SelectRecords(qry, &templates); err != nil {
		errMsg := fmt.Sprintf("failed to retrieve all templates from db: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	// decrypt the allowance usernames
	// map of usernames so dont decrypt the same username multiple times
	uniqueUsers := make(map[string]string, len(templates))
	for _, t := range templates {
		// dumping into a map so can decrypt concurrently
		uniqueUsers[t.Username] = "" // placeholder for decypted value; encrpyted value is the key
	}

	// decrypt the usernames concurrently
	var (
		mu sync.Mutex
		wg sync.WaitGroup

		errChan = make(chan error, len(uniqueUsers))
	)

	for encrypted := range uniqueUsers {

		wg.Add(1)
		go func(encrypted string, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			decrypted, err := s.cryptor.DecryptServiceData(encrypted)
			if err != nil {
				ch <- fmt.Errorf("%v", err)

				return
			}

			mu.Lock()
			uniqueUsers[encrypted] = string(decrypted)
			mu.Unlock()
		}(encrypted, errChan, &wg)
	}

	wg.Wait()
	close(errChan)

	// check for any decryption errors
	errCount := len(errChan)
	if errCount > 0 {
		var sb strings.Builder
		counter := 0
		for err := range errChan {
			sb.WriteString(fmt.Sprintf("%v", err))
			if counter < errCount-1 {
				sb.WriteString("; ")
			}
			counter++
		}
		errMsg := fmt.Sprintf("failed to decrypt %d username(s): %v", errCount, sb.String())
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	// consolidate to unique template records with usernames slices
	uniqueTemplates := make(map[string]exotasks.Template, len(templates))
	for _, t := range templates {
		if _, ok := uniqueTemplates[t.Id]; !ok {
			uniqueTemplates[t.Id] = exotasks.Template{
				Id:          t.Id,
				Name:        t.Name,
				Description: t.Description,
				Cadence:     t.Cadence,
				Category:    t.Category,
				Slug:        t.Slug,
				CreatedAt:   t.CreatedAt,
				IsArchived:  t.IsArchived,
				Assignees:   make([]profile.User, 0),
			}
		}

		template := uniqueTemplates[t.Id]
		template.Assignees = append(template.Assignees, profile.User{
			Username: uniqueUsers[t.Username],
		})
		uniqueTemplates[t.Id] = template
	}

	// convert map to slice
	result := make([]exotasks.Template, 0, len(uniqueTemplates))
	for _, t := range uniqueTemplates {
		result = append(result, t)
	}

	s.logger.Info(fmt.Sprintf("successfully retrieved %d template records", len(result)))

	return result, nil
}

// GetTemplate is a concrete implementation of the GetTemplate method in the TemplateService interface
func (s *templateService) GetTemplate(slug string) (*exotasks.Template, error) {

	// validate slug
	// redundant check, but good practice
	if !validate.IsValidUuid(slug) {
		errMsg := fmt.Sprintf("invalid template slug: %s", slug)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	// look up the template record by slug
	qry := `
	SELECT 
		t.uuid, 
		t.name, 
		t.description, 
		t.cadence, 
		t.category, 
		t.slug, 
		t.created_at, 
		t.is_archived,
		a.username
	FROM template t 
		LEFT OUTER JOIN template_allowance ta ON t.uuid = ta.template_uuid
		LEFT OUTER JOIN allowance a ON ta.allowance_uuid = a.uuid
		WHERE t.slug = ?`
	// need to look up as slice because of join/more than one user could be assigned
	var templates []TemplateAssignee
	if err := s.db.SelectRecords(qry, &templates, slug); err != nil {
		if err == sql.ErrNoRows {
			errMsg := fmt.Sprintf("template record not found for slug: %s", slug)
			s.logger.Error(errMsg)
			return nil, fmt.Errorf(errMsg)
		}
		errMsg := fmt.Sprintf("failed to retrieve template record from db: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
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

			decrypted, err := s.cryptor.DecryptServiceData(templates[i].Username)
			if err != nil {
				ch <- fmt.Errorf("%v", err)
				return
			}

			templates[i].Username = string(decrypted)
		}(i, errChan, &wg)
	}

	wg.Wait()
	close(errChan)

	// check for any decryption errors
	errCount := len(errChan)
	if errCount > 0 {
		var sb strings.Builder
		counter := 0
		for err := range errChan {
			sb.WriteString(fmt.Sprintf("%v", err))
			if counter < errCount-1 {
				sb.WriteString("; ")
			}
			counter++
		}
		errMsg := fmt.Sprintf("failed to decrypt %d username(s): %v", errCount, sb.String())
		return nil, fmt.Errorf(errMsg)
	}

	// consolidate to unique template record with usernames slice
	uniqueTemplate := exotasks.Template{
		Id:          templates[0].Id,
		Name:        templates[0].Name,
		Description: templates[0].Description,
		Cadence:     templates[0].Cadence,
		Category:    templates[0].Category,
		Slug:        templates[0].Slug,
		CreatedAt:   templates[0].CreatedAt,
		IsArchived:  templates[0].IsArchived,
		Assignees:   make([]profile.User, 0),
	}
	for _, t := range templates {

		uniqueTemplate.Assignees = append(uniqueTemplate.Assignees, profile.User{
			Username: t.Username,
		})
	}

	s.logger.Info(fmt.Sprintf("successfully retrieved template record for slug %s", slug))

	return &uniqueTemplate, nil
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
	t := Template{
		Id:          id.String(),
		Name:        cmd.Name,
		Description: cmd.Description,
		Cadence:     cmd.Cadence,
		Category:    cmd.Category,
		Slug:        slug.String(),
		CreatedAt:   data.CustomTime{Time: time.Now().UTC()},
		IsArchived:  false,
	}

	qry := `INSERT INTO template (uuid, name, description, cadence, category, slug, created_at, is_archived)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, t); err != nil {
		errMsg := fmt.Sprintf("failed to insert template record in to db: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	s.logger.Info(fmt.Sprintf("created new template record: %v", t))

	return &t, nil
}

// UpdateTemplate is a concrete implementation of the UpdateTemplate method in the TemplateService interface
func (s *templateService) UpdateTemplate(t *Template) error {

	// validate the template record
	// redundant check, but good practice
	if err := t.Validate(); err != nil {
		errMsg := fmt.Sprintf("invalid template record: %v", err)
		s.logger.Error(errMsg)
		return fmt.Errorf(errMsg)
	}

	// update the template record in the database
	qry := `UPDATE template
			SET name = ?, 
				description = ?, 
				cadence = ?, 
				category = ?, 
				is_archived = ?
			WHERE uuid = ?`
	if err := s.db.UpdateRecord(qry, t.Name, t.Description, t.Cadence, t.Category, t.IsArchived, t.Id); err != nil {
		errMsg := fmt.Sprintf("failed to update template record in db: %v", err)
		s.logger.Error(errMsg)
		return fmt.Errorf(errMsg)
	}

	s.logger.Info(fmt.Sprintf("successfully updated template record: %s", t.Id))

	return nil
}

// CreateAllowanceXref is a concrete implementation of the CreateAllowanceXref method in the TemplateService interface
func (s *templateService) CreateAllowanceXref(t *Template, a *exotasks.Allowance) (*AllowanceTemplateXref, error) {

	// create the new xref record
	xref := AllowanceTemplateXref{
		TemplateId:  t.Id,
		AllowanceId: a.Id,
		CreatedAt:   data.CustomTime{Time: time.Now().UTC()},
	}

	qry := `INSERT INTO template_allowance ( template_uuid, allowance_uuid, created_at)
			VALUES (?, ?, ?)`
	if err := s.db.InsertRecord(qry, xref); err != nil {
		errMsg := fmt.Sprintf("failed to insert allowance-template xref record in to db: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	s.logger.Info(fmt.Sprintf("successfully created xref record between allowance %s and template %s", a.Username, t.Name))

	return &xref, nil
}

// DeleteAllowanceXref is a concrete implementation of the DeleteAllowanceXref method in the TemplateService interface
func (s *templateService) DeleteAllowanceXref(t *Template, a *exotasks.Allowance) error {

	// delete the xref record from the database
	qry := `DELETE FROM template_allowance 
			WHERE template_uuid = ? AND allowance_uuid = ?`
	if err := s.db.DeleteRecord(qry, t.Id, a.Id); err != nil {
		errMsg := fmt.Sprintf("failed to delete allowance-template xref record from db: %v", err)
		s.logger.Error(errMsg)
		return fmt.Errorf(errMsg)
	}

	s.logger.Info(fmt.Sprintf("successfully deleted xref record between allowance %s and template %s", a.Username, t.Name))

	return nil
}

// CreateTaskXref is a concrete implementation of the CreateTaskXref method in the TemplateService interface
func (s *templateService) CreateTaskXref(t *Template, ta *tasks.Task) (*TemplateTaskXref, error) {

	// create the new xref record
	xref := TemplateTaskXref{
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

	return &xref, nil
}
