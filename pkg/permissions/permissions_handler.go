package permissions

import (
	"apprentice/internal/util"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
)

var readPermissionsAllowed = []string{"r:apprentice:permissions:*"}
var writePermissionsAllowed = []string{"w:apprentice:permissions:*"}

// Handler is an interface that aggregates all permission handler functionality
type Handler interface {

	// HandlePermissions handles HTTP requests for /permissions endpoint
	HandlePermissions(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new Handler interface, returning a pointer to the concrete implementation
func NewHandler(s Service, s2s, iam jwt.Verifier) Handler {
	return &handler{
		service: s,
		s2s:     s2s,
		iam:     iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackagePermissions)).
			With(slog.String(util.ComponentKey, util.ComponentPermissions)),
	}
}

var _ Handler = (*handler)(nil)

// handler is the concrete implementation of the Handler interface
type handler struct {
	service Service
	s2s     jwt.Verifier
	iam     jwt.Verifier

	logger *slog.Logger
}

// HandlePermissions is the concrete implementation of the Handler method which
// handles HTTP requests for the /permissions endpoint.
func (h *handler) HandlePermissions(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		// Handle GET request for permissions\
		h.getPermissions(w, r)
		return
	case http.MethodPost:
		// Handle POST request to create a new permission
		// h.createPermission(w, r)
		// return
	default:
		// Handle unsupported methods
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "Method not allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

// getAllPermissions handles GET requests for the /permissions endpoint, returning all permissions from the permissions table.
func (h *handler) getPermissions(w http.ResponseWriter, r *http.Request) {

	// validate the service token
	s2sToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(readPermissionsAllowed, s2sToken); err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to authorize s2s token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	// need subject to determine fine grain permissions
	iamToken := r.Header.Get("Authorization")
	if _, err := h.iam.BuildAuthorized(readPermissionsAllowed, iamToken); err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to authorize iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// scope check is enough, no need to get permissions for this endpoint at this time.

	// get all permissions
	permissions, err := h.service.GetAllPermissions()
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get permissions: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permissions",
		}
		e.SendJsonErr(w)
		return
	}

	// respond with permissions
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(permissions); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode permissions: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode permissions",
		}
		e.SendJsonErr(w)
		return
	}
}
