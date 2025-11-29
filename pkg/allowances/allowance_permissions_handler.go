package allowances

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/apprentice/internal/util"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// scopes needed to interact with allowance permissions endpoints
var (
	readAllowancePermissionsAllowed   = []string{"r:apprentice:*", "r:apprentice:allowances:permissions:*"}
	updateAllowancePermissionsAllowed = []string{"w:apprentice:*", "w:apprentice:allowances:permissions:*"}
)

// AllowancePermissionsHandler defines the interface for handling requests related to allowance permissions
type AllowancePermissionsHandler interface {

	// HandlePermissions handles requests related to allowance permissions
	HandlePermissions(w http.ResponseWriter, r *http.Request)
}

// NewAllowancePermissionsHandler creates a new AllowancePermissionsHandler interface
// and returns a pointer to a concrete implementation of the interface
func NewAllowancePermissionsHandler(s Service, s2s, iam jwt.Verifier) AllowancePermissionsHandler {
	return &allowancePermissionsHandler{
		service:   s,
		s2sVerify: s2s,
		iamVerify: iam,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageAllowances)).
			With(slog.String(util.ComponentKey, util.ComponentAllownacePermisssionsHandler)),
	}
}

var _ AllowancePermissionsHandler = (*allowancePermissionsHandler)(nil)

// allowancePermissionsHandler is the concrete implementation of the AllowancePermissionsHandler interface
type allowancePermissionsHandler struct {
	service   Service
	s2sVerify jwt.Verifier
	iamVerify jwt.Verifier

	logger *slog.Logger
}

// HandlePermissions is the concrete implementation of the AllowancePermissionsHandler method
// It handles requests related to allowance permissions
func (h *allowancePermissionsHandler) HandlePermissions(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.getAllowancePermissions(w, r)
		return
	case http.MethodPost:
		h.updateAllowancePermissions(w, r)
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

// getAllowancePermissions handles the retrieval of an allowance account's permissions
func (h *allowancePermissionsHandler) getAllowancePermissions(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate the s2s token
	s2sToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2sVerify.BuildAuthorized(readAllowancePermissionsAllowed, s2sToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate the iam token
	iamToken := r.Header.Get("Authorization")
	if _, err := h.iamVerify.BuildAuthorized(readAllowancePermissionsAllowed, iamToken); err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get query parameters -> email address of the allowance account
	username := r.URL.Query().Get("username")
	if username == "" {
		log.Error("url missing username query parameter")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "missing username query parameter",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the username is a well-formed email address
	if err := validate.IsValidEmail(username); err != nil {
		log.Error("failed to validate username parmameter", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// lookup the allowance account's permissions by username/email
	_, permissions, err := h.service.GetAllowancePermissions(username)
	if err != nil {
		h.logger.Error("failed to get allowance account permissions for user", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    "failed to get allowance account permissions for user ",
		}
		e.SendJsonErr(w)
		return
	}

	// NOTE: IT IS IMPORTANT TO RETURN THE EMPTY ARRAY IF NO PERMISSIONS ARE FOUND
	// BECAUSE IT IS POSSIBLE FOR AN ALLOWANCE ACCOUNT TO HAVE NO PERMISSIONS
	if permissions == nil {
		h.logger.Warn("no permissions found for allowance account")
	}

	// respond with the permissions
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(permissions); err != nil {
		h.logger.Error("failed to encode permissions for allowance account", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to encode permissions for allowance account",
		}
		e.SendJsonErr(w)
		return
	}
}

// updateAllowancePermissions handles the updating of allowance's permissions
func (h *allowancePermissionsHandler) updateAllowancePermissions(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// verify the service token
	s2sToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2sVerify.BuildAuthorized(updateAllowancePermissionsAllowed, s2sToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// verify the iam token
	iamToken := r.Header.Get("Authorization")
	authedUser, err := h.iamVerify.BuildAuthorized(updateAllowancePermissionsAllowed, iamToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// get the request body
	var cmd exo.UpdatePermissionsCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error("failed to decode request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.Validate(); err != nil {
		log.Error("failed to validate request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// lookup the allowance account by username/email
	// in this case the entity is the allowance account username/email
	allowance, err := h.service.GetByUser(cmd.Entity)
	if err != nil {
		log.Error("failed to find allowance account for user", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// update the permissions for the allowance account
	added, removed, err := h.service.UpdateAllowancePermissions(ctx, allowance, cmd.Permissions)
	if err != nil {
		log.Error("failed to update permissions for allowance account permissions", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// audit log
	var updatedPermissions []any
	if len(added) > 0 {
		for _, p := range added {
			updatedPermissions = append(updatedPermissions, slog.String("added_permission", p.Name))
		}
	}

	if len(removed) > 0 {
		for _, p := range removed {
			updatedPermissions = append(updatedPermissions, slog.String("removed permission %s", p.Name))
		}
	}

	if len(updatedPermissions) > 0 {
		log = log.With(updatedPermissions...)
		log.Info(fmt.Sprintf("successfully updated permissions for allowance account %s", allowance.Username))
	} else {
		log.Info(fmt.Sprintf("no permission changes made for allowance account %s", allowance.Username))
	}

	// respond 204: No Content
	w.WriteHeader(http.StatusNoContent)
}
