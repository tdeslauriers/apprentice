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

	// hydrate the assignees records in the templates
	for i, _ := range templates {
		for j, _ := range templates[i].Assignees {
			for _, a := range assignees {
				if templates[i].Assignees[j].Username == a.Username {
					templates[i].Assignees[j] = a
					break
				}
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
		Id:          template.Id,
		Name:        template.Name,
		Description: template.Description,
		Cadence:     template.Cadence,
		Category:    template.Category,
		Slug:        template.Slug,
		CreatedAt:   template.CreatedAt,
		IsArchived:  template.IsArchived,
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
