package permissions

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/apprentice/internal/util"

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
}

// NewHandler creates a new Handler interface, returning a pointer to the concrete implementation
func NewHandler(s Service, s2s, iam jwt.Verifier) Handler {
	return &handler{
		service: s,
		s2s:     s2s,
		iam:     iam,

		logger: slog.Default().
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

		// get slug if exists
		slug := r.PathValue("slug")
		if slug != "" {

			h.getPermissions(w, r)
			return
		} else {
			// Handle GET request for a specific permission
			h.getPermission(w, r)
			return
		}
	case http.MethodPost:
		// Handle POST request to create a new permission
		h.createPermission(w, r)
		return
	case http.MethodPut:
		// Handle PUT (actually a post) request to update a specific permission
		h.updatePermission(w, r)
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

// getAllPermissions handles GET requests for the /permissions endpoint, returning all permissions from the permissions table.
func (h *handler) getPermissions(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate the service token
	s2sToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(readPermissionsAllowed, s2sToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	// need subject to determine fine grain permissions
	iamToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(readPermissionsAllowed, iamToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// scope check is enough, no need to get permissions for this endpoint at this time.

	// get all permissions
	_, permissions, err := h.service.GetAllPermissions()
	if err != nil {
		log.Error("failed to get permissions", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d permissions", len(permissions)))

	// respond with permissions
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(permissions); err != nil {
		log.Error("failed to encode permissions", "err", err.Error())
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

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate the service token
	s2sToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(readPermissionsAllowed, s2sToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	// need subject to determine fine grain permissions
	iamToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(readPermissionsAllowed, iamToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// extract slug from request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get the permission by slug
	p, err := h.service.GetPermissionBySlug(slug)
	if err != nil {
		log.Error("failed to get permission by slug", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permission",
		}
		e.SendJsonErr(w)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved permission %s", p.Name))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(p); err != nil {
		log.Error("failed to encode permission", "err", err.Error())
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

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate the service token
	s2sToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(writePermissionsAllowed, s2sToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	iamToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(writePermissionsAllowed, iamToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// parse the permission from the request body
	var cmd exo.Permission
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode permission", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode permission",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the permission
	if err := cmd.Validate(); err != nil {
		log.Error("failed to validate permission", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// validate service name is correct
	if strings.ToLower(strings.TrimSpace(cmd.ServiceName)) != util.ServiceApprentice {
		log.Error("failed to validate service name",
			"err", fmt.Sprintf("invalid service must be %s", util.ServiceApprentice))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("invalid service must be %s", util.ServiceApprentice),
		}
		e.SendJsonErr(w)
		return
	}

	// build permission persistence model
	p := &exo.PermissionRecord{
		ServiceName: cmd.ServiceName,
		Permission:  strings.ToUpper(strings.TrimSpace(cmd.Permission)),
		Name:        strings.TrimSpace(cmd.Name),
		Description: cmd.Description,
		Active:      cmd.Active,
	}

	// create the permission in persistence
	permission, err := h.service.CreatePermission(p)
	if err != nil {
		log.Error("failed to create permission", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// audit log
	log.Info(fmt.Sprintf("successfully created permission: %s", permission.Name))

	// respond with the created permission
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(permission); err != nil {
		log.Error("failed to json encode permission", "err", err.Error())
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

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate the service token
	s2sToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(writePermissionsAllowed, s2sToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	iamToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(writePermissionsAllowed, iamToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// extract slug from request URL
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// parse the permission from the request body
	var cmd exo.PermissionRecord
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode permission", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode permission",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the permission
	if err := cmd.Validate(); err != nil {
		log.Error("failed to validate permission", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get the existing permission by slug
	p, err := h.service.GetPermissionBySlug(slug)
	if err != nil {
		log.Error("failed to get permission from slug in request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// service field dropped for update, however, good to check it is correct
	// since an incorrect value would indicate tampering
	if strings.ToLower(strings.TrimSpace(cmd.ServiceName)) != util.ServiceApprentice {
		log.Error("failed to validate service name", "err", fmt.Sprintf("service name must be %s", util.ServiceApprentice))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("invalid service must be %s", util.ServiceApprentice),
		}
		e.SendJsonErr(w)
		return
	}

	// update the permission fields
	record := &exo.PermissionRecord{
		Id:          p.Id,
		ServiceName: p.ServiceName,                                      // may not be updated, keep the existing service
		Permission:  strings.ToUpper(strings.TrimSpace(cmd.Permission)), // may not be updated, keep the existing permission
		Name:        strings.TrimSpace(cmd.Name),                        // may not be updated, keep the existing name
		Description: cmd.Description,
		Active:      cmd.Active,
		Slug:        p.Slug,      // keep the existing slug
		CreatedAt:   p.CreatedAt, // keep the existing created_at timestamp
	}

	// update the permission in persistence
	if err := h.service.UpdatePermission(record); err != nil {
		log.Error("failed to update permission", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to update permission",
		}
		e.SendJsonErr(w)
		return
	}

	// audit log
	var updatedFields []any

	if p.Permission != record.Permission {
		updatedFields = append(updatedFields,
			slog.String("previous_permission", record.Permission),
			slog.String("updated_permission", p.Permission))
	}

	if p.Name != record.Name {
		updatedFields = append(updatedFields,
			slog.String("previous_name", record.Name),
			slog.String("updated_name", p.Name))
	}

	if p.Description != record.Description {
		updatedFields = append(updatedFields,
			slog.String("previous_description", record.Description),
			slog.String("updated_description", p.Description))
	}

	if p.Active != record.Active {
		updatedFields = append(updatedFields,
			slog.Bool("previous_active", record.Active),
			slog.Bool("updated_active", p.Active))
	}

	if len(updatedFields) > 0 {
		log = log.With(updatedFields...)
		log.Info(fmt.Sprintf("successfully updated permission %s", p.Slug))
	}

	// respond with the updated permission
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(record); err != nil {
		log.Error("failed to json encode updated permission", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode updated permission",
		}
		e.SendJsonErr(w)
		return
	}
}
