package templates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/tdeslauriers/apprentice/internal/util"
	"github.com/tdeslauriers/shaw/pkg/api/user"

	"github.com/tdeslauriers/apprentice/internal/allowances"
	"github.com/tdeslauriers/apprentice/internal/tasks"
	api "github.com/tdeslauriers/apprentice/pkg/api/allowances"
	"github.com/tdeslauriers/apprentice/pkg/api/templates"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// endoint authorization scopes
var readTemplatesAllowed = []string{"r:apprentice:templates:*"}
var writeTemplatesAllowed = []string{"w:apprentice:templates:*"}

// Handler is an interface to handle template endpoint functionality
type Handler interface {

	// HandleGetTemplates is a handler for all requests to the /templates endpoint
	HandleTemplates(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new Handler interface, returning a pointer to the concrete implementation
func NewHandler(
	s Service,
	a allowances.Service,
	t tasks.Service,
	s2s jwt.Verifier,
	iam jwt.Verifier,
	p provider.S2sTokenProvider,
	i *connect.S2sCaller,
) Handler {

	return &handler{
		template:  s,
		allowance: a,
		task:      t,
		s2s:       s2s,
		iam:       iam,
		tkn:       p,
		identity:  i,

		logger: slog.Default().
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
	identity  *connect.S2sCaller

	logger *slog.Logger
}

// HandleTemplates is a concrete impl of a handler for all requests to the /templates endpoint
func (h *handler) HandleTemplates(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:

		// get slug if it exists
		slug := r.PathValue("slug")
		switch slug {
		case "":
			h.getTemplates(w, r)
			return
		case "assignees":
			h.getAssignees(w, r)
			return
		default:
			h.getTemplate(w, r)
			return
		}
	case http.MethodPost:
		h.createTemplate(w, r)
		return
	case http.MethodPut:
		h.updateTemplate(w, r)
		return
	default:
		// get telemetry from request
		tel := connect.ObtainTelemetry(r, h.logger)
		log := h.logger.With(tel.TelemetryFields()...)

		log.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return
	}
}

// getAssignees returns all users who may be assigned to tasks, ie the have the *:apprentice:task:* scope.
// it makes a call to the identity service to hydrate the list with user data.
func (h *handler) getAssignees(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(readTemplatesAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(readTemplatesAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// get identity service token
	identityS2sToken, err := h.tkn.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		log.Error("failed to get identity service token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// call identity service to get all users with the <r/w>:apprentice:task:* scopes
	encoded := url.QueryEscape("r:apprentice:tasks:* w:apprentice:tasks:*")
	users, err := connect.GetServiceData[[]user.User](
		ctx,
		h.identity,
		fmt.Sprintf("/s2s/users/groups?scopes=%s", encoded),
		identityS2sToken,
		"",
	)
	if err != nil {
		log.Error("failed to get users from identity service", "err", err.Error())
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// get allowance records from the database
	allowances, err := h.allowance.GetAllowances()
	if err != nil {
		log.Error("failed to get allowances from database", "err", err.Error())
		h.allowance.HandleAllowanceError(w, err)
		return
	}

	// build assignees list by matching users to allowance records
	assignees := make([]templates.Assignee, 0, len(users))
	for _, user := range users {
		for _, allowance := range allowances {
			if user.Username == allowance.Username {
				assignees = append(assignees, templates.Assignee{
					Username:      user.Username,
					Firstname:     user.Firstname,
					Lastname:      user.Lastname,
					AllowanceSlug: allowance.Slug,
				})
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(assignees); err != nil {
		log.Error("failed to encode assignees to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode assignees to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// getTemplates calls the template service to get all templates
// Note: this may include calls to the identity service to hydrate the assignees records
func (h *handler) getTemplates(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(readTemplatesAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(readTemplatesAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// get all temps from the database
	temps, err := h.template.GetTemplates()
	if err != nil {
		log.Error("failed to get templates from database", "err", err.Error())
		h.template.HandleServiceError(w, err)
		return
	}

	// get all assignees from the database
	// get identity service token
	identityS2sToken, err := h.tkn.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		log.Error("failed to get identity service token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// call identity service to get all users with the <r/w>:apprentice:task:* scopes
	encoded := url.QueryEscape("r:apprentice:tasks:* w:apprentice:tasks:*")
	assignees, err := connect.GetServiceData[[]user.User](
		ctx,
		h.identity,
		fmt.Sprintf("/s2s/users/groups?scopes=%s", encoded),
		identityS2sToken,
		"",
	)
	if err != nil {
		log.Error("failed to get users from identity service", "err", err.Error())
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// check that assignees were returned
	if len(assignees) < 1 {
		log.Error("failed to get assignees from identity service")
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get assignees from identity service",
		}
		e.SendJsonErr(w)
		return
	}

	assigneeMap := make(map[string]user.User, len(assignees))
	for _, a := range assignees {
		assigneeMap[a.Username] = a
	}

	// hydrate the assignees records in the templates
	for i := range temps {
		for j := range temps[i].Assignees {
			if user, ok := assigneeMap[temps[i].Assignees[j].Username]; ok {
				temps[i].Assignees[j] = templates.Assignee{
					Username:      temps[i].Assignees[j].Username,
					Firstname:     user.Firstname,
					Lastname:      user.Lastname,
					AllowanceSlug: temps[i].Assignees[j].AllowanceSlug,
				}
			} else {
				log.Error(fmt.Sprintf("failed to hydrate assignee: %s", temps[i].Assignees[j].Username))
				e := connect.ErrorHttp{
					StatusCode: http.StatusInternalServerError,
					Message:    "failed to hydrate assignees",
				}
				e.SendJsonErr(w)
				return
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(temps); err != nil {
		log.Error("failed to encode templates to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode templates to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// createTemplate handles web requests to create a new template
func (h *handler) createTemplate(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(writeTemplatesAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(writeTemplatesAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// decode request body
	var cmd templates.TemplateCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate request body", "err", err.Error())
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
		log.Error("failed to get valid assignees", "err", err.Error())
		h.allowance.HandleAllowanceError(w, err)
		return
	}

	if len(missing) > 0 {
		log.Error("templates creating command includes assigness who do not have allowance records",
			"err", fmt.Sprintf("invalid assignees: %s", strings.Join(missing, "; ")))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "invalid assignees",
		}
		e.SendJsonErr(w)
		return
	}

	// create new template record in the database
	template, err := h.template.CreateTemplate(ctx, cmd)
	if err != nil {

		log.Error("failed to create new template record", "err", err.Error())
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
		go func(u *api.Allowance, t *templates.TemplateRecord, errXref chan error, wgXref *sync.WaitGroup) {

			defer wgXref.Done()

			// create the xref record between template and allowance
			if _, err := h.template.CreateAllowanceXref(ctx, t, u); err != nil {
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
			if _, err = h.template.CreateTaskXref(ctx, t, task); err != nil {
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
	if len(errXref) > 0 {
		var errs []error
		for e := range errXref {
			errs = append(errs, e)
		}
		log.Error("failed to create xref records for new template record", "errs", errors.Join(errs...))
	}

	// prepare response object
	response := templates.Template{
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

	// audit log
	h.logger.Info(fmt.Sprintf("successfully created new template: %s", template.Name))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error("failed to encode createed template to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode created template to json",
		}
		e.SendJsonErr(w)
		return
	}
}

// getTemplate is a concrete impl of a handler for the GET /template/slug endpoint
// it validates the incoming request, and then calls the template service to get a single template
func (h *handler) getTemplate(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(readTemplatesAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(readTemplatesAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
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
		log.Error("failed to get template from database", "err", err.Error())
		h.template.HandleServiceError(w, err)
		return
	}

	// get all assignees from identity service
	// get identity service token
	identityS2sToken, err := h.tkn.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		log.Error("failed to get identity service token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// call identity service to get all users with the <r/w>:apprentice:task:* scopes
	encoded := url.QueryEscape("r:apprentice:tasks:* w:apprentice:tasks:*")
	assignees, err := connect.GetServiceData[[]user.User](
		ctx,
		h.identity,
		fmt.Sprintf("/s2s/users/groups?scopes=%s", encoded),
		identityS2sToken,
		"",
	)
	if err != nil {
		log.Error("failed to get users from identity service", "err", err.Error())
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// check that assignees were returned
	if len(assignees) < 1 {
		log.Error("failed to get assignees from identity service", "err", "no assignees returned")
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "no assignees returned from identity service",
		}
		e.SendJsonErr(w)
		return
	}

	// hydrate the assignees records in the template
	for i := range template.Assignees {
		for _, a := range assignees {
			if template.Assignees[i].Username == a.Username {
				template.Assignees[i].Firstname = a.Firstname
				template.Assignees[i].Lastname = a.Lastname
				break
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(template); err != nil {
		log.Error("failed to encode template to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// udpateTemplate is a concrete impl of a handler for the POST /template/slug endpoint
// it validates the incoming request, and then calls the template service to update a template
func (h *handler) updateTemplate(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(writeTemplatesAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(writeTemplatesAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// get slug from the request url
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to get valid slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get existing record via slug lookup
	// no reason to parse/decode request body if slug is not real value
	record, err := h.template.GetTemplate(slug)
	if err != nil {
		log.Error("failed to get template from database", "err", err.Error())
		h.template.HandleServiceError(w, err)
		return
	}

	// decode request body
	var cmd templates.TemplateCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate cadence
	if err := cmd.Cadence.IsValidCadence(); err != nil {
		log.Error("failed to validate cadence", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate category
	if err := cmd.Category.IsValidCategory(); err != nil {
		log.Error("failed to validate category", "err", err.Error())
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
		log.Error("failed to get assignees", "err", err.Error())
		h.allowance.HandleAllowanceError(w, err)
		return
	}

	if len(missing) > 0 {
		log.Error("templates update command includes assigness who do not have allowance records",
			"err", fmt.Sprintf("invalid assignees: %s", strings.Join(missing, "; ")))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    "invalid assignees",
		}
		e.SendJsonErr(w)
		return
	}

	// prepare the template for update\
	updated := templates.TemplateRecord{
		Id:           record.Id, // not allowed to update
		Name:         cmd.Name,
		Description:  cmd.Description,
		Cadence:      cmd.Cadence,
		Category:     cmd.Category,
		IsCalculated: cmd.IsCalculated,
		Slug:         record.Slug,      // not allowed to update
		CreatedAt:    record.CreatedAt, // not allowed to update
		IsArchived:   cmd.IsArchived,
	}

	// compare new user assignees to existing
	// if the template.Assignees not in 'existing', delete the xrefs
	// if the 'existing' usernames not in template.Assignees, add the xrefs
	var (
		toDelete = make(map[string]bool, len(record.Assignees)) // key is username
		toAdd    = make(map[string]bool, len(existing))         // key is allowance uuid
	)

	// loop for template_allowance records to remove
	for _, assigned := range record.Assignees {
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
		for _, assigned := range record.Assignees {
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
	go func(t *templates.TemplateRecord, errDb chan error, wgDb *sync.WaitGroup) {
		defer wgDb.Done()
		if err := h.template.UpdateTemplate(ctx, t); err != nil {
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
				if err := h.template.DeleteAllowanceXref(ctx, &updated, a); err != nil {
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

				if _, err := h.template.CreateAllowanceXref(ctx, &updated, &api.Allowance{Id: allowanceId}); err != nil {
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
	if len(errDb) > 0 {
		var errs []error
		for e := range errDb {
			errs = append(errs, e)
		}
		log.Error("failed to update template record", "errs", errors.Join(errs...))
		h.template.HandleServiceError(w, errors.Join(errs...))
		return
	}

	// audit log
	var changes []any
	if record.Name != updated.Name {
		changes = append(changes,
			slog.String("previous_name", record.Name),
			slog.String("updated_name", updated.Name),
		)
	}

	if record.Description != updated.Description {
		changes = append(changes,
			slog.String("previous_description", record.Description),
			slog.String("updated_description", updated.Description),
		)
	}

	if record.Cadence != updated.Cadence {
		changes = append(changes,
			slog.String("previous_cadence", string(record.Cadence)),
			slog.String("updated_cadence", string(updated.Cadence)),
		)
	}

	if record.Category != updated.Category {
		changes = append(changes,
			slog.String("previous_category", string(record.Category)),
			slog.String("updated_category", string(updated.Category)),
		)
	}

	if record.IsCalculated != updated.IsCalculated {
		changes = append(changes,
			slog.Bool("previous_is_calculated", record.IsCalculated),
			slog.Bool("updated_is_calculated", updated.IsCalculated),
		)
	}

	if record.IsArchived != updated.IsArchived {
		changes = append(changes,
			slog.Bool("previous_is_archived", record.IsArchived),
			slog.Bool("updated_is_archived", updated.IsArchived),
		)
	}

	if len(changes) > 0 {
		log = log.With(changes...)
		log.Info(fmt.Sprintf("successfully updated template slug %s", slug))
	} else {
		log.Warn(fmt.Sprintf("executed update request for template slug %s but no changes were made", slug))
	}

	// return no content
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		log.Error("failed to encode updaed template to json", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode updated template to json",
		}
		e.SendJsonErr(w)
		return
	}
}
