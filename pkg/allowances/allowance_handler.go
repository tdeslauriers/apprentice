package allowances

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tdeslauriers/apprentice/internal/util"
	"github.com/tdeslauriers/apprentice/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/shaw/pkg/api/user"
)

// authorization
var getAllowancesAllowed []string = []string{"r:apprentice:allowances:*"}
var postAllowancesAllowed []string = []string{"w:apprentice:allowances:*"}

type AllowancesHandler interface {
	// HandleAllowances handles  all requests to /allowances endpoint
	HandleAllowances(w http.ResponseWriter, r *http.Request)
}

// NewAllowancesHandler creates a new AllowancesHandler interface, returning a pointer to the concrete implementation
func NewAllowancesHandler(
	s Service,
	p permissions.Service,
	s2s jwt.Verifier,
	iam jwt.Verifier,
	tkn provider.S2sTokenProvider,
	identity *connect.S2sCaller,
) AllowancesHandler {

	return &allowancesHandler{
		service:    s,
		permission: p,
		s2s:        s2s,
		iam:        iam,
		tkn:        tkn,
		identity:   identity,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageAllowances)).
			With(slog.String(util.ComponentKey, util.ComponentAllowances)),
	}
}

var _ AllowancesHandler = (*allowancesHandler)(nil)

// allowancesHandler is the concrete implementation of the AllowancesHandler interface
type allowancesHandler struct {
	service    Service
	permission permissions.Service
	s2s        jwt.Verifier
	iam        jwt.Verifier
	tkn        provider.S2sTokenProvider
	identity   *connect.S2sCaller

	logger *slog.Logger
}

// HandleAllowances handles all requests to /allowances endpoint
func (h *allowancesHandler) HandleAllowances(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:

		// get slug if exists
		slug := r.PathValue("slug")
		if slug == "" {

			h.getAll(w, r)
			return
		} else {
			h.getAllowance(w, r)
			return
		}
	case http.MethodPost:
		h.createAllowance(w, r)
		return
	case http.MethodPut:
		h.updateAllowance(w, r)
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

// getAll handles the GET request to get all allowances
func (h *allowancesHandler) getAll(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(getAllowancesAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(getAllowancesAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// scope auth check is sufficient, no need to get permissions for this endpoint at this time.

	// get all allowances
	allowances, err := h.service.GetAllowances()
	if err != nil {
		log.Error("failed to get allowances", "err", err.Error())
		h.service.HandleAllowanceError(w, err)
		return
	}

	log.Info(fmt.Sprintf("successfully retrieved %d allowance accounts", len(allowances)))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(allowances); err != nil {
		log.Error("failed to json encode response", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// getAllowance handles the GET request to get a specific allowance by slug
func (h *allowancesHandler) getAllowance(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(getAllowancesAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(getAllowancesAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// get permissions
	pm, _, err := h.permission.GetAllowancePermissions(authedUser.Claims.Subject)
	if err != nil {
		log.Error("failed to get permissions", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permissions",
		}
		e.SendJsonErr(w)
		return
	}

	// NOTE: not using concurrently here because if permissions are wrong, error immediately
	// and not fetch and decrypt the allowance account record
	// quick check permissions
	if _, ok := pm[util.PermissionPayroll]; !ok {
		log.Error("user does not have permission to get allowance account")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "user does not have permission to get allowance account",
		}
		e.SendJsonErr(w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid allowance slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get allowance
	allowance, err := h.service.GetBySlug(slug)
	if err != nil {
		log.Error("failed to get allowance by slug", "err", err.Error())
		h.service.HandleAllowanceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		log.Error("failed to json encode response", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// createAllowance handles the POST request to create a new allowance account
func (h *allowancesHandler) createAllowance(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(postAllowancesAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(postAllowancesAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// get permissions and validate user has permission to create allowance accounts, ie, payroll permission
	pm, _, err := h.permission.GetAllowancePermissions(authedUser.Claims.Subject)
	if err != nil {
		log.Error("failed to get permissions", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permissions",
		}
		e.SendJsonErr(w)
		return
	}

	if _, ok := pm[util.PermissionPayroll]; !ok {
		log.Error("user does not have permission to create allowance account")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "user does not have permission to create allowance account",
		}
		e.SendJsonErr(w)
		return
	}

	// decode request body
	var cmd CreateAllowanceCmd
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

	// Need to validate the user exists in the identity service, has a valid dob, etc.
	// Note: user slug will be taken as source of truth since that is the unique identifier
	// the identity service expects.  Also it is harder to fake a slug than an email.

	// get service token
	s2sToken, err := h.tkn.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		log.Error("failed to get identity service token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// get user info from identity service --> service endpoint --> /s2s/users/{slug}
	user, err := connect.GetServiceData[user.User](
		ctx,
		h.identity,
		fmt.Sprintf("/s2s/users/%s", cmd.Slug),
		s2sToken,
		"",
	)
	if err != nil {
		log.Error("failed to get user info from identity service", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// validate submitted email matches the user's email from the identity service
	if strings.TrimSpace(cmd.Username) != user.Username {
		log.Error("failed to create allowance acocunt",
			"err", "submitted email does not match user account email")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "submitted email does not match user account email",
		}
		e.SendJsonErr(w)
		return
	}

	// validate user dob is on file
	if user.BirthDate == "" {
		log.Error("failed to create allowance account",
			"err", "user account does not have a birth date on file")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "failed to create allowance account because user account does not have a birth date on file",
		}
		e.SendJsonErr(w)
		return
	}

	// validatte submitted dob matches the user's dob from the identity service
	if strings.TrimSpace(cmd.BirthDate) != user.BirthDate {
		log.Error("failed to create allowance account",
			"err", "submitted birth date does not match user account birth date")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "submitted birth date does not match user account birth date",
		}
		e.SendJsonErr(w)
		return
	}

	// validate account is not disabled
	if !user.Enabled {
		log.Error("failed to create allowance account", "err", "user account is disabled")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "user account is disabled",
		}
		e.SendJsonErr(w)
		return
	}

	// validate account is not locked
	if user.AccountLocked {
		log.Error("failed to create allowance account", "err", "account is locked")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "account is locked",
		}
		e.SendJsonErr(w)
		return
	}

	// validate account is not expired
	if user.AccountExpired {
		log.Error("failed to create allowance account", "err", "account is expired")
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "account is expired",
		}
		e.SendJsonErr(w)
		return
	}

	// create allowance account
	// account creation will check if an account already exists for the user
	// and return an error if it does
	allowance, err := h.service.CreateAllowance(cmd.Username)
	if err != nil {
		log.Error("failed to create allowance account", "err", err.Error())
		h.service.HandleAllowanceError(w, err)
		return
	}

	// audit log
	log.Info(fmt.Sprintf("allowance account successfully created for user %s", user.Username))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		log.Error(fmt.Sprintf("/allowances post-handler failed to json encode response: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// updateAllowance handles the PUT request to update an allowance account
func (h *allowancesHandler) updateAllowance(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(postAllowancesAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize service token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(postAllowancesAllowed, accessToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		log.Error("failed to get valid slug from request", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

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

	// get permissions and validate user has permission to update allowance accounts, ie, payroll permission
	pm, _, err := h.permission.GetAllowancePermissions(authedUser.Claims.Subject)
	if err != nil {
		log.Error("failed to get permissions", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permissions",
		}
		e.SendJsonErr(w)
		return
	}

	// check if user has payroll permission
	if _, ok := pm[util.PermissionPayroll]; !ok {
		log.Error("user does not have permission to update allowance account")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "user does not have permission to update allowance account",
		}
		e.SendJsonErr(w)
		return
	}

	// get allowance by slug to check update values for business logic issues
	allowance, err := h.service.GetBySlug(slug)
	if err != nil {
		log.Error("failed to get allowance by slug", "err", err.Error())
		h.service.HandleAllowanceError(w, err)
		return
	}

	// validate update values --> business logic
	if err := h.service.ValidateUpdate(cmd, *allowance); err != nil {
		log.Error("failed to validate allowance update", "err", err.Error())
		h.service.HandleAllowanceError(w, err)
		return
	}

	// prepare updated allowance
	// used as return object if update successful
	updated := Allowance{
		// slug index not provided by GetAllowance(slug)
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
			slog.String("previous_balance", fmt.Sprintf("%.2f", float64(allowance.Balance)/100)),
			slog.String("new_balance", fmt.Sprintf("%.2f", float64(updated.Balance)/100)),
			slog.String("change_type", "credit"),
			slog.String("change_amount", fmt.Sprintf("%.2f", float64(cmd.Credit)/100)))
	}

	if cmd.Debit > 0 {
		updatedFields = append(updatedFields,
			slog.String("previous_balance", fmt.Sprintf("%.2f", float64(allowance.Balance)/100)),
			slog.String("new_balance", fmt.Sprintf("%.2f", float64(updated.Balance)/100)),
			slog.String("change_type", "debit"),
			slog.Float64("change_amount", float64(cmd.Debit)/100),
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
