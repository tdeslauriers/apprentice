package templates

import (
	"apprentice/internal/util"
	"apprentice/pkg/allowances"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

var readTemplatesAllowed = []string{"r:apprentice:template:*"}
var writeTemplatesAllowed = []string{"w:apprentice:template:*"}

// Handler is an interface to handle template endpoint functionality
type Handler interface {

	// HandleGetAssignees is a handler for the GET /templates/assignees endpoint,
	// returning all users who may be assigned to tasks, ie the have the *:apprentice:task:* scope.
	HandleGetAssignees(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new Handler interface, returning a pointer to the concrete implementation
func NewHandler(s Service, a allowances.Service, s2s, iam jwt.Verifier, p provider.S2sTokenProvider, i connect.S2sCaller) Handler {
	return &handler{
		template:  s,
		allowance: a,
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
	encoded := url.QueryEscape("r:apprentice:task:* w:apprentice:task:*")
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
