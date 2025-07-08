package permissions

import (
	"apprentice/internal/util"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
)

var readPermissionsAllowed = []string{"r:apprentice:permissions:*"}
var writePermissionsAllowed = []string{"w:apprentice:permissions:*"}

// Handler is an interface that aggregates all permission handler functionality
type Handler interface {

	// HandlePermissions handles HTTP requests for /permissions endpoint
	HandlePermissions(w http.ResponseWriter, r *http.Request)

	// HandlePermission handles HTTP requests for /permissions/{slug} endpoint
	HandlePermission(w http.ResponseWriter, r *http.Request)
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
		h.createPermission(w, r)
		return
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

// HandlePermission is the concrete implementation of the Handler method which
// handles HTTP requests for the /permissions/{slug} endpoint.
func (h *handler) HandlePermission(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		// Handle GET request for a specific permission
		h.getPermission(w, r)
		return
	case http.MethodPost:
		// Handle PUT (actually a post) request to update a specific permission
		h.updatePermission(w, r)
		return
	default:
		// Handle unsupported methods
		h.logger.Error(fmt.Sprintf("unsupported method %s for /permissions/{slug}", r.Method))
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

// getPermission handles GET requests for the /permissions/{slug} endpoint, returning a specific permission.
func (h *handler) getPermission(w http.ResponseWriter, r *http.Request) {

	// validate the service token
	s2sToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(readPermissionsAllowed, s2sToken); err != nil {
		h.logger.Error(fmt.Sprintf("/permissions handler failed to authorize s2s token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	iamToken := r.Header.Get("Authorization")
	if _, err := h.iam.BuildAuthorized(readPermissionsAllowed, iamToken); err != nil {
		h.logger.Error(fmt.Sprintf("/permissions handler failed to authorize iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// extract slug from request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get slug from request: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid slug in request",
		}
		e.SendJsonErr(w)
		return
	}

	// get the permission by slug
	p, err := h.service.GetPermissionBySlug(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get permission by slug '%s': %v", slug, err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permission",
		}
		e.SendJsonErr(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(p); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode permission: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode permission",
		}
		e.SendJsonErr(w)
		return
	}
}

// createPermission handles POST requests for the /permissions endpoint, creating a new permission.
func (h *handler) createPermission(w http.ResponseWriter, r *http.Request) {

	// validate the service token
	s2sToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(writePermissionsAllowed, s2sToken); err != nil {
		h.logger.Error(fmt.Sprintf("/permissions handler failed to authorize s2s token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	iamToken := r.Header.Get("Authorization")
	authorized, err := h.iam.BuildAuthorized(writePermissionsAllowed, iamToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/permissions handler failed to authorize iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// parse the permission from the request body
	var cmd exo.Permission
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode permission: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode permission",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the permission
	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("invalid permission: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("invalid permission: %v", err),
		}
		e.SendJsonErr(w)
		return
	}

	// validate service name is correct
	if strings.ToLower(strings.TrimSpace(cmd.Service)) != util.ServiceApprentice {
		errMsg := fmt.Sprintf("invalid service name '%s': must be %s", cmd.Service, util.ServiceApprentice)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// build permission persistence model
	p := &Permission{
		Name:        cmd.Name,
		Service:     cmd.Service,
		Description: cmd.Description,
		Active:      cmd.Active,
	}

	// create the permission in persistence
	permission, err := h.service.CreatePermission(p)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to create permission: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to create permission",
		}
		e.SendJsonErr(w)
		return
	}

	// audit log
	h.logger.Info(fmt.Sprintf("%s - %s created by %s", permission.Id, &permission.Name, authorized.Claims.Subject))

	// respond with the created permission
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(permission); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode permission: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode permission",
		}
		e.SendJsonErr(w)
		return
	}
}

// updatePermission is a helper method that implementsthe functionality for
// PUT requests for the /permissions/{slug} endpoint, updating an existing permission.
func (h *handler) updatePermission(w http.ResponseWriter, r *http.Request) {

	// validate the service token
	s2sToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(writePermissionsAllowed, s2sToken); err != nil {
		h.logger.Error(fmt.Sprintf("/permissions handler failed to authorize s2s token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	iamToken := r.Header.Get("Authorization")
	authorized, err := h.iam.BuildAuthorized(writePermissionsAllowed, iamToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/permissions handler failed to authorize iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// extract slug from request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get slug from request: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid slug in request",
		}
		e.SendJsonErr(w)
		return
	}

	// parse the permission from the request body
	var cmd Permission
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("failed to decode permission: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode permission",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the permission
	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("invalid permission: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("invalid permission: %v", err),
		}
		e.SendJsonErr(w)
		return
	}

	// get the existing permission by slug
	p, err := h.service.GetPermissionBySlug(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get permission by slug '%s': %v", slug, err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permission from slug in request",
		}
		e.SendJsonErr(w)
		return
	}

	// service field dropped for update, however, good to check it is correct
	// since an incorrect value would indicate tampering
	if strings.ToLower(strings.TrimSpace(cmd.Service)) != util.ServiceApprentice {
		errMsg := fmt.Sprintf("invalid service name '%s': must be %s", cmd.Service, util.ServiceApprentice)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// update the permission fields
	record := &Permission{
		Id:          p.Id,
		Name:        cmd.Name,
		Service:     p.Service, // may not be updated, keep the existing service
		Description: cmd.Description,
		Active:      cmd.Active,
		Slug:        p.Slug,      // keep the existing slug
		CreatedAt:   p.CreatedAt, // keep the existing created_at timestamp
	}

	// update the permission in persistence
	if err := h.service.UpdatePermission(record); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update permission: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to update permission",
		}
		e.SendJsonErr(w)
		return
	}

	// audit log
	if p.Name != record.Name {
		h.logger.Info(fmt.Sprintf("permission %s's name updated from %s to %s updated by %s", p.Id, p.Name, record.Name, authorized.Claims.Subject))
	}

	if p.Description != record.Description {
		h.logger.Info(fmt.Sprintf("permission %s's description updated from %s to %s updated by %s", p.Id, p.Description, record.Description, authorized.Claims.Subject))
	}

	if p.Active != record.Active {
		h.logger.Info(fmt.Sprintf("permission %s's active status updated from %t to %t updated by %s", p.Id, p.Active, record.Active, authorized.Claims.Subject))
	}

	// respond with the updated permission
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(record); err != nil {
		h.logger.Error(fmt.Sprintf("failed to json encode updated permission: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode updated permission",
		}
		e.SendJsonErr(w)
		return
	}
}
