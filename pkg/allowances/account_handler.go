package allowances

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/tdeslauriers/apprentice/internal/util"

	"github.com/tdeslauriers/apprentice/pkg/permissions"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
)

// authorization
var getAccountAllowed []string = []string{"r:apprentice:account:*", "r:apprentice:allowances:*"}
var postAccountAllowed []string = []string{"w:apprentice:account:*", "w:apprentice:allowances:*"}

// AccountHandler is an interface that performs functionality a user may take on their own account
type AccountHandler interface {
	// HandleAccount is a method to handle account related functionality
	HandleAccount(w http.ResponseWriter, r *http.Request)
}

// NewAccountHandler creates a new AccountHandler interface, returning a pointer to the concrete implementation
func NewAccountHandler(s Service, p permissions.Service, s2s, iam jwt.Verifier) AccountHandler {
	return &accountHandler{
		service:     s,
		permissions: p,
		s2s:         s2s,
		iam:         iam,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageAllowances)).
			With(slog.String(util.ComponentKey, util.ComponentAllowanceAccount)),
	}
}

var _ AccountHandler = (*accountHandler)(nil)

// accountHandler is the concrete implementation of the AccountHandler interface
type accountHandler struct {
	service     Service
	permissions permissions.Service
	s2s         jwt.Verifier
	iam         jwt.Verifier

	logger *slog.Logger
}

// HandleAccount is a concrete implementation of the HandleAccount method in the AccountHandler interface
func (h *accountHandler) HandleAccount(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// check the method
	switch r.Method {
	case http.MethodGet:
		h.getAccount(w, r, log)
		return
	case http.MethodPut:
		h.updateAccount(w, r, log)
		return
	default:
		log.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetAccount is the concrete implementation of the method to retreive an allowance account
func (h *accountHandler) getAccount(w http.ResponseWriter, r *http.Request, log *slog.Logger) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(getAccountAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(getAccountAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// get user's permissions
	pm, _, err := h.permissions.GetAllowancePermissions(authedUser.Claims.Subject)
	if err != nil {
		log.Error("failed to get account user's permissions", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// check of permissions
	_, isRemittee := pm[util.PermissionRemittee]
	_, isPayroll := pm[util.PermissionPayroll]

	// payroll can still only see their own account via this endpoint
	if !isRemittee && !isPayroll {
		log.Error("failed to get allowance account", "err", "user does not have correct permissions")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "user does not have correct permissions",
		}
		e.SendJsonErr(w)
		return
	}

	// get the remittee
	a, err := h.service.GetByUser(authedUser.Claims.Subject)
	if err != nil {
		log.Error("failed to get allowance account for user",
			"err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	log.Info("user successfully retrieved their allowance account")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(a); err != nil {
		log.Error("failed to json encode allowance account response",
			"err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleUpdateAccount is the concrete implementation of the method to update a user's specfic account
func (h *accountHandler) updateAccount(w http.ResponseWriter, r *http.Request, log *slog.Logger) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(postAccountAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = h.logger.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(postAccountAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// decode request body
	var cmd UpdateAllowanceCmd
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

	// NOTE: not using concurrency here because if permissions are wrong, error immediately
	// and not fetch and decrypt the allowance account record
	// get permissions
	pm, _, err := h.permissions.GetAllowancePermissions(authedUser.Claims.Subject)
	if err != nil {
		log.Error("failed to get account user's permissions", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permissions",
		}
		e.SendJsonErr(w)
		return
	}

	// quick check permissions
	_, isPayroll := pm[util.PermissionPayroll]
	_, isRemittee := pm[util.PermissionRemittee]

	// if the user is not a payroll or remittee, return forbidden
	if !isPayroll && !isRemittee {
		log.Error("failed to update allowance account", "err", "user does not have correct permissions")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "user does not have correct permissions",
		}
		e.SendJsonErr(w)
		return
	}

	// NOTE: at this time, remitees cannot update their own accounts at all
	// this may change.
	if !isPayroll {
		log.Error("failed to update allowance account", "err", "user does not have correct permissions")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "user does not have correct permissions",
		}
		e.SendJsonErr(w)
		return
	}

	// get allowance
	allowance, err := h.service.GetByUser(authedUser.Claims.Subject)
	if err != nil {
		log.Error("failed to get allowance account for user", "err", err.Error())
		h.service.HandleAllowanceError(w, err)
		return
	}

	// validate update values --> business logic
	if err := h.service.ValidateUpdate(cmd, *allowance); err != nil {
		log.Error("failed to validate allowance account update business logic", "err", err.Error())
		h.service.HandleAllowanceError(w, err)
		return
	}

	// prepare updated allowance
	// used as return object if update successful
	updated := Allowance{

		Id:           allowance.Id,
		Balance:      allowance.Balance + cmd.Credit - cmd.Debit,
		Username:     allowance.Username,
		Slug:         allowance.Slug,
		CreatedAt:    allowance.CreatedAt,
		UpdatedAt:    data.CustomTime{Time: time.Now().UTC()},
		IsArchived:   cmd.IsArchived,
		IsActive:     cmd.IsActive,
		IsCalculated: cmd.IsCalculated,
	}

	// update allowance account
	if err := h.service.UpdateAllowance(&updated); err != nil {
		log.Error("failed to update allowance account", "err", err.Error())
		h.service.HandleAllowanceError(w, err)
		return
	}

	// audit log
	var updatedFields []any
	if cmd.Credit > 0 {
		updatedFields = append(updatedFields,
			slog.String("previous_balance", fmt.Sprintf("%.2f", float64(allowance.Balance/100))),
			slog.String("new_balance", fmt.Sprintf("%.2f", float64(updated.Balance/100))),
			slog.String("change_type", "credit"),
			slog.String("change_amount", fmt.Sprintf("%.2f", float64(cmd.Credit/100))))
	}

	if cmd.Debit > 0 {
		updatedFields = append(updatedFields,
			slog.String("previous_balance", fmt.Sprintf("%.2f", float64(allowance.Balance/100))),
			slog.String("new_balance", fmt.Sprintf("%.2f", float64(updated.Balance/100))),
			slog.String("change_type", "debit"),
			slog.Float64("change_amount", float64(cmd.Debit/100)),
		)
	}

	if cmd.IsArchived != allowance.IsArchived {
		updatedFields = append(updatedFields,
			slog.Bool("previous_is_archived", allowance.IsArchived),
			slog.Bool("new_is_archived", updated.IsArchived),
		)
	}

	if cmd.IsActive != allowance.IsActive {
		updatedFields = append(updatedFields,
			slog.Bool("previous_is_active", allowance.IsActive),
			slog.Bool("new_is_active", updated.IsActive),
		)
	}

	if cmd.IsCalculated != allowance.IsCalculated {
		updatedFields = append(updatedFields,
			slog.Bool("previous_is_calculated", allowance.IsCalculated),
			slog.Bool("new_is_calculated", updated.IsCalculated),
		)
	}

	log = log.With(updatedFields...)
	log.Info("user successfully updated their allowance account")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		log.Error("failed to json encode response", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}
