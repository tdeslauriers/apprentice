package allowances

import (
	"apprentice/internal/util"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

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
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
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
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "method not allowed",
		}
		e.SendJsonErr(w)
		return
	}
}

// getAllowancePermissions handles the retrieval of an allowance account's permissions
func (h *allowancePermissionsHandler) getAllowancePermissions(w http.ResponseWriter, r *http.Request) {

	// validate the s2s token
	s2sToken := r.Header.Get("ServiceAuthorization")
	if _, err := h.s2sVerify.BuildAuthorized(readAllowancePermissionsAllowed, s2sToken); err != nil {
		h.logger.Error(fmt.Sprintf("allowance permissions endpoint failed to verify service token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate the iam token
	iamToken := r.Header.Get("Authorization")
	if _, err := h.iamVerify.BuildAuthorized(readAllowancePermissionsAllowed, iamToken); err != nil {
		h.logger.Error(fmt.Sprintf("allowance permissions endpoint failed to verify iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get query parameters -> email address of the allowance account
	username := r.URL.Query().Get("username")
	if username == "" {
		h.logger.Error("allowance permissions endpoint missing username query parameter")
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "missing username query parameter",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the username is a well-formed email address
	if err := validate.IsValidEmail(username); err != nil {
		h.logger.Error(fmt.Sprintf("allowance permissions endpoint received an invalid username: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("invalid username: %v", err),
		}
		e.SendJsonErr(w)
		return
	}

	// lookup the allowance account's permissions by username/email
	_, permissions, err := h.service.GetAllowancePermissions(username)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get allowance account permissions for user %s: %v", username, err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    fmt.Sprintf("allowance account not found for user %s", username),
		}
		e.SendJsonErr(w)
		return
	}

	// NOTE: IT IS IMPORTANT TO RETURN THE EMPTY ARRAY IF NO PERMISSIONS ARE FOUND
	// BECAUSE IT IS POSSIBLE FOR AN ALLOWANCE ACCOUNT TO HAVE NO PERMISSIONS
	if permissions == nil {
		h.logger.Warn(fmt.Sprintf("no permissions found for allowance account %s", username))
	}

	// respond with the permissions
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(permissions); err != nil {
		h.logger.Error(fmt.Sprintf("failed to encode permissions for allowance account %s: %v", username, err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to encode permissions for allowance account %s", username),
		}
		e.SendJsonErr(w)
		return
	}
}

// updateAllowancePermissions handles the updating of allowance's permissions
func (h *allowancePermissionsHandler) updateAllowancePermissions(w http.ResponseWriter, r *http.Request) {

	// verify the service token
	s2sToken := r.Header.Get("Authorization")
	_, err := h.s2sVerify.BuildAuthorized(updateAllowancePermissionsAllowed, s2sToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("allowance permissions endpoint failed to verify service token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// verify the iam token
	iamToken := r.Header.Get("Authorization")
	authorized, err := h.iamVerify.BuildAuthorized(updateAllowancePermissionsAllowed, iamToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("allowance permissions endpoint failed to verify iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get the request body
	var cmd exo.UpdatePermissionsCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("error decoding request body: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate the request body
	if err := cmd.Validate(); err != nil {
		h.logger.Error(fmt.Sprintf("error validating request body: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("invalid request body: %v", err),
		}
		e.SendJsonErr(w)
		return
	}

	// lookup the allowance account by username/email
	// in this case the entity is the allowance account username/email
	allowance, err := h.service.GetByUser(cmd.Entity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get allowance account for user %s: %v", cmd.Entity, err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    fmt.Sprintf("allowance account not found for user %s", cmd.Entity),
		}
		e.SendJsonErr(w)
		return
	}

	// update the permissions for the allowance account
	added, removed, err := h.service.UpdateAllowancePermissions(allowance, cmd.Permissions)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to update permissions for allowance account %s: %v", allowance.Slug, err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to update permissions for allowance account %s", allowance.Slug),
		}
		e.SendJsonErr(w)
		return
	}

	// audit log
	if added != nil && len(added) > 0 {
		for _, p := range added {
			h.logger.Info(fmt.Sprintf("permission %s to allowance account %s by %s", p.Name, allowance.Slug, authorized.Claims.Subject))
		}
	}

	if removed != nil && len(removed) > 0 {
		for _, p := range removed {
			h.logger.Info(fmt.Sprintf("removed permission %s from allowance account %s by %s", p.Name, allowance.Slug, authorized.Claims.Subject))
		}
	}

	// respond 204: No Content
	w.WriteHeader(http.StatusNoContent)
}
