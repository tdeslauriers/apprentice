package templates

import (
	"apprentice/internal/util"
	"apprentice/pkg/allowances"
	"apprentice/pkg/tasks"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	exotasks "github.com/tdeslauriers/carapace/pkg/tasks"
)

var readTemplatesAllowed = []string{"r:apprentice:templates:*"}
var writeTemplatesAllowed = []string{"w:apprentice:templates:*"}

// Handler is an interface to handle template endpoint functionality
type Handler interface {

	// HandleGetAssignees is a handler for the GET /templates/assignees endpoint,
	// returning all users who may be assigned to tasks, ie the have the *:apprentice:task:* scope.
	HandleGetAssignees(w http.ResponseWriter, r *http.Request)

	// HandleGetTemplates is a handler for all requests to the /templates endpoint
	HandleTemplates(w http.ResponseWriter, r *http.Request)

	// HandlePostTemplate is a handler for the POST /templates/slug endpoint
	HandleTemplate(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new Handler interface, returning a pointer to the concrete implementation
func NewHandler(s Service, a allowances.Service, t tasks.Service, s2s, iam jwt.Verifier, p provider.S2sTokenProvider, i connect.S2sCaller) Handler {
	return &handler{
		template:  s,
		allowance: a,
		task:      t,
		s2s:       s2s,
		iam:       iam,
		tkn:       p,
		identity:  i,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageTemplates)).
			With(slog.String(util.ComponentKey, util.ComponentTemplates)),
	}
}

var _ Handler = (*handler)(nil)

// handler is the concrete implementation of the Handler interface
type handler struct {
	template  Service
	allowance allowances.Service
	task      tasks.Service
	s2s       jwt.Verifier
	iam       jwt.Verifier
	tkn       provider.S2sTokenProvider
	identity  connect.S2sCaller

	logger *slog.Logger
}

// HandleGetAssignees is a concrete impl of a handler for the GET /templates/assignees endpoint,
// returning all users who may be assigned to tasks, ie the have the *:apprentice:task:* scope.
// it makes a call to the identity service to hydrate the list with user data.
func (h *handler) HandleGetAssignees(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(readTemplatesAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/templates/assignees failed to authorize service token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	if _, err := h.iam.BuildAuthorized(readTemplatesAllowed, accessToken); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get identity service token
	identityS2sToken, err := h.tkn.GetServiceToken(util.ServiceIdentity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/templates/assignees handler failed to get identity service token: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// call identity service to get all users with the <r/w>:apprentice:task:* scopes
	var assignees []profile.User
	encoded := url.QueryEscape("r:apprentice:tasks:* w:apprentice:tasks:*")
	if err := h.identity.GetServiceData(fmt.Sprintf("/s2s/users/groups?scopes=%s", encoded), identityS2sToken, "", &assignees); err != nil {
		h.logger.Error(fmt.Sprintf("/templates/assignees handler failed to get tasks service users from identity service: %v", err))
		h.identity.RespondUpstreamError(err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(assignees); err != nil {
		h.logger.Error(fmt.Sprintf("/templates/assignees handler failed to json encode response: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode json response",
		}
		e.SendJsonErr(w)
		return
	}
}

// HandleTemplates is a concrete impl of a handler for all requests to the /templates endpoint
func (h *handler) HandleTemplates(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGetTemplates(w, r)
		return
	case http.MethodPost:
		h.handlePostTemplates(w, r)
		return
	default:
		h.logger.Error(fmt.Sprintf("/templates handler received unsupported method: %s", r.Method))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

// HandleTemplate is a concrete impl of a handler  /template/slug endpoint
func (h *handler) HandleTemplate(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.getTemplate(w, r)
		return
	case http.MethodPost:
		h.postTemplate(w, r)
		return
	default:
		h.logger.Error(fmt.Sprintf("/template/slug handler received unsupported method: %s", r.Method))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetTemplates is a concrete impl of a handler for the GET /templates endpoint
// it validates the incoming request, and then calls the template service to get all templates
// Note: this may include calls to the identity service to hydrate the assignees records
func (h *handler) handleGetTemplates(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(readTemplatesAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to authorize service token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	if _, err := h.iam.BuildAuthorized(readTemplatesAllowed, accessToken); err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to authorize iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get all templates from the database
	templates, err := h.template.GetTemplates()
	if err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to get templates: %v", err))
		h.template.HandleServiceError(w, err)
		return
	}

	// get all assignees from the database
	// get identity service token
	identityS2sToken, err := h.tkn.GetServiceToken(util.ServiceIdentity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/templates/assignees handler failed to get identity service token: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// call identity service to get all users with the <r/w>:apprentice:task:* scopes
	var assignees []profile.User
	encoded := url.QueryEscape("r:apprentice:tasks:* w:apprentice:tasks:*")
	if err := h.identity.GetServiceData(fmt.Sprintf("/s2s/users/groups?scopes=%s", encoded), identityS2sToken, "", &assignees); err != nil {
		h.logger.Error(fmt.Sprintf("/templates/assignees handler failed to get tasks service users from identity service: %v", err))
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// check that assignees were returned
	if len(assignees) < 1 {
		h.logger.Error(fmt.Sprintf("/templates/assignees handler failed to get assignees from identity service: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get assignees from identity service",
		}
		e.SendJsonErr(w)
		return
	}

	assigneeMap := make(map[string]profile.User, len(assignees))
	for _, a := range assignees {
		assigneeMap[a.Username] = a
	}

	// hydrate the assignees records in the templates
	for i := range templates {
		for j := range templates[i].Assignees {
			if user, ok := assigneeMap[templates[i].Assignees[j].Username]; ok {
				templates[i].Assignees[j] = user
			} else {
				h.logger.Error(fmt.Sprintf("/templates handler failed to hydrate assignee: %s", templates[i].Assignees[j].Username))
				e := connect.ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    "failed to hydrate assignee",
				}
				e.SendJsonErr(w)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(templates); err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to encode response: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// handlePostTemplates is a concrete impl of a handler for the POST /templates endpoint
// it validates the incoming request, and then calls the template service to create a new template
func (h *handler) handlePostTemplates(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(writeTemplatesAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to authorize service token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	if _, err := h.iam.BuildAuthorized(writeTemplatesAllowed, accessToken); err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to authorize iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// decode request body
	var cmd exotasks.TemplateCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to decode request body: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to validate request body: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get assignees from database
	existing, missing, err := h.allowance.GetValidUsers(cmd.Assignees)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to get valid assignees: %v", err))
		h.allowance.HandleAllowanceError(w, err)
		return
	}

	if len(missing) > 0 {
		h.logger.Error(fmt.Sprintf("/templates handler found missing assignees: %v", missing))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "failed to generate task template due to invalid assignees: " + fmt.Sprintf("%v", strings.Join(missing, ", ")),
		}
		e.SendJsonErr(w)
		return
	}

	// create new template record in the database
	template, err := h.template.CreateTemplate(cmd)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to create new template: %v", err))
		h.template.HandleServiceError(w, err)
		return
	}

	// set up go concurrency to put insert the xref records
	var (
		wgXref sync.WaitGroup
		// each user must be connected to the template + task
		errXref = make(chan error, len(existing))
	)

	for _, user := range existing {
		wgXref.Add(1)
		go func(u *exotasks.Allowance, t *Template, errXref chan error, wgXref *sync.WaitGroup) {

			defer wgXref.Done()

			// create the xref record between template and allowance
			if _, err := h.template.CreateAllowanceXref(t, u); err != nil {
				errXref <- fmt.Errorf("failed to create xref record for user %s and template %s: %v", u.Username, t.Name, err)
				return
			}

			// generate the task record
			task, err := h.task.CreateTask()
			if err != nil {
				errXref <- fmt.Errorf("failed to create initial task record for user %s and template %s: %v", u.Username, t.Name, err)
				return
			}

			// create the xref record between task and template
			if _, err = h.template.CreateTaskXref(t, task); err != nil {
				errXref <- fmt.Errorf("failed to create xref record for task %s and template %s: %v", task.Id, t.Name, err)
				return
			}

			// create the xref record between task and allowance
			if _, err = h.task.CreateAllowanceXref(task, u); err != nil {
				errXref <- fmt.Errorf("failed to create xref record for task %s and user %s: %v", task.Id, u.Username, err)
				return
			}

		}(&user, template, errXref, &wgXref)
	}

	wgXref.Wait()
	close(errXref)

	// check for errors in the xref creation
	errCount := len(errXref)
	if errCount > 0 {
		var sb strings.Builder
		counter := 0
		for err := range errXref {
			sb.WriteString(err.Error())
			counter++
			if counter < errCount {
				sb.WriteString("; ")
			}
		}
		h.logger.Error(fmt.Sprintf("/templates handler failed to create xref records: %s", sb.String()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to create xref records",
		}
		e.SendJsonErr(w)
		return
	}

	h.logger.Info(fmt.Sprintf("/templates handler successfully created new template: %s", template.Name))

	// prepare response object
	response := exotasks.Template{
		Id:           template.Id,
		Name:         template.Name,
		Description:  template.Description,
		Cadence:      template.Cadence,
		Category:     template.Category,
		IsCalculated: template.IsCalculated,
		Slug:         template.Slug,
		CreatedAt:    template.CreatedAt,
		IsArchived:   template.IsArchived,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to encode response: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response",
		}
		e.SendJsonErr(w)
		return
	}

}

// getTemplate is a concrete impl of a handler for the GET /template/slug endpoint
// it validates the incoming request, and then calls the template service to get a single template
func (h *handler) getTemplate(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(readTemplatesAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to authorize service token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	if _, err := h.iam.BuildAuthorized(readTemplatesAllowed, accessToken); err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to authorize iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to get valid slug: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to get valid slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get template from the database
	template, err := h.template.GetTemplate(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to get template: %v", err))
		h.template.HandleServiceError(w, err)
		return
	}

	// get all assignees from identity service
	// get identity service token
	identityS2sToken, err := h.tkn.GetServiceToken(util.ServiceIdentity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to get identity service token: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// call identity service to get all users with the <r/w>:apprentice:task:* scopes
	var assignees []profile.User
	encoded := url.QueryEscape("r:apprentice:tasks:* w:apprentice:tasks:*")
	if err := h.identity.GetServiceData(fmt.Sprintf("/s2s/users/groups?scopes=%s", encoded), identityS2sToken, "", &assignees); err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to get tasks service users from identity service: %v", err))
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// check that assignees were returned
	if len(assignees) < 1 {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to get assignees from identity service: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get assignees from identity service",
		}
		e.SendJsonErr(w)
		return
	}

	// hydrate the assignees records in the template
	for i, _ := range template.Assignees {
		for _, a := range assignees {
			if template.Assignees[i].Username == a.Username {
				template.Assignees[i] = a
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(template); err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to encode response: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// postTemplate is a concrete impl of a handler for the POST /template/slug endpoint
// it validates the incoming request, and then calls the template service to update a template
func (h *handler) postTemplate(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(writeTemplatesAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to authorize service token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	if _, err := h.iam.BuildAuthorized(writeTemplatesAllowed, accessToken); err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to authorize iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get slug from the request url
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to get valid slug: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to get valid slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get existing record via slug lookup
	// no reason to parse/decode request body if slug is not real value
	template, err := h.template.GetTemplate(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to get template: %v", err))
		h.template.HandleServiceError(w, err)
		return
	}

	// decode request body
	var cmd exotasks.TemplateCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to decode request body: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to validate request body: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate cadence
	if err := cmd.Cadence.IsValidCadence(); err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to validate cadence: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate category
	if err := cmd.Category.IsValidCategory(); err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to validate category: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get assignees from database
	// ie, it checks if the emails submitted in the request body are valid and allowed
	existing, missing, err := h.allowance.GetValidUsers(cmd.Assignees)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/templates handler failed to get valid assignees: %v", err))
		h.allowance.HandleAllowanceError(w, err)
		return
	}

	if len(missing) > 0 {
		h.logger.Error(fmt.Sprintf("/templates handler found missing assignees: %v", missing))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "failed to update task template due to invalid assignees: " + fmt.Sprintf("%v", strings.Join(missing, ", ")),
		}
		e.SendJsonErr(w)
		return
	}

	// prepare the template for update\
	updated := Template{
		Id:           template.Id, // not allowed to update
		Name:         cmd.Name,
		Description:  cmd.Description,
		Cadence:      cmd.Cadence,
		Category:     cmd.Category,
		IsCalculated: cmd.IsCalculated,
		Slug:         template.Slug,      // not allowed to update
		CreatedAt:    template.CreatedAt, // not allowed to update
		IsArchived:   cmd.IsArchived,
	}

	// compare new user assignees to existing
	// if the template.Assignees not in 'existing', delete the xrefs
	// if the 'existing' usernames not in template.Assignees, add the xrefs
	var (
		toDelete = make(map[string]bool, len(template.Assignees)) // key is username
		toAdd    = make(map[string]bool, len(existing))           // key is allowance uuid
	)

	// loop for template_allowance records to remove
	for _, assigned := range template.Assignees {
		exists := false
		for _, allowance := range existing {
			if assigned.Username == allowance.Username {
				exists = true
				break
			}
		}
		if !exists {
			toDelete[assigned.Username] = true
		}
	}

	// loop for new assignees to add
	for _, allowance := range existing {
		exists := false
		for _, assigned := range template.Assignees {
			if assigned.Username == allowance.Username {
				exists = true
				break
			}
		}
		if !exists {
			toAdd[allowance.Id] = true
		}
	}

	// make database updates concurrently
	var (
		wgDb  sync.WaitGroup
		errDb = make(chan error, len(toDelete)+len(toAdd))
	)

	// update the template record
	wgDb.Add(1)
	go func(t *Template, errDb chan error, wgDb *sync.WaitGroup) {
		defer wgDb.Done()
		if err := h.template.UpdateTemplate(t); err != nil {
			errDb <- err
			return
		}
	}(&updated, errDb, &wgDb)

	// delete the xref records if applicable
	if len(toDelete) > 0 {
		for username := range toDelete {

			wgDb.Add(1)
			go func(username string, errDb chan error, wgDb *sync.WaitGroup) {
				defer wgDb.Done()

				// get the allowance record from the database
				a, err := h.allowance.GetByUser(username)
				if err != nil {
					errDb <- err
					return
				}

				// delete the xref record between template and allowance
				if err := h.template.DeleteAllowanceXref(&updated, a); err != nil {
					errDb <- err
					return
				}
			}(username, errDb, &wgDb)
		}
	}

	// add the xref records if applicable
	if len(toAdd) > 0 {
		for allowanceId := range toAdd {
			wgDb.Add(1)
			go func(allowanceId string, errDb chan error, wgDb *sync.WaitGroup) {
				defer wgDb.Done()

				if _, err := h.template.CreateAllowanceXref(&updated, &exotasks.Allowance{Id: allowanceId}); err != nil {
					errDb <- err
					return
				}
			}(allowanceId, errDb, &wgDb)
		}
	}

	// wait for all goroutines to finish
	// close the error channel
	wgDb.Wait()
	close(errDb)

	// check for errors in the database updates
	errCount := len(errDb)
	if errCount > 0 {
		var sb strings.Builder
		counter := 0
		for err := range errDb {
			sb.WriteString(err.Error())
			if counter < errCount {
				sb.WriteString("; ")
			}
			counter++
		}

		h.logger.Error(fmt.Sprintf("/template/slug handler failed to update template in database: %s", sb.String()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to update template",
		}
		e.SendJsonErr(w)
		return
	}

	// log audit trail (template record only: xrefs are logged in service upon creation/deletion)
	if template.Name != updated.Name {
		h.logger.Info(fmt.Sprintf("/template/slug handler updated template name from %s to %s", template.Name, updated.Name))
	}

	if template.Description != updated.Description {
		h.logger.Info(fmt.Sprintf("/template/slug handler updated template description from %s to %s", template.Description, updated.Description))
	}

	if template.Cadence != updated.Cadence {
		h.logger.Info(fmt.Sprintf("/template/slug handler updated template cadence from %s to %s", template.Cadence, updated.Cadence))
	}

	if template.Category != updated.Category {
		h.logger.Info(fmt.Sprintf("/template/slug handler updated template category from %s to %s", template.Category, updated.Category))
	}

	if template.IsCalculated != updated.IsCalculated {
		h.logger.Info(fmt.Sprintf("/template/slug handler updated template is_calculated from %t to %t", template.IsCalculated, updated.IsCalculated))
	}

	if template.IsArchived != updated.IsArchived {
		h.logger.Info(fmt.Sprintf("/template/slug handler updated template is_archived from %t to %t", template.IsArchived, updated.IsArchived))
	}

	// return no content
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		h.logger.Error(fmt.Sprintf("/template/slug handler failed to encode response: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode response",
		}
		e.SendJsonErr(w)
		return
	}
}
