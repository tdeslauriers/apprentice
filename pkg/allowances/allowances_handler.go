package allowances

import (
	"apprentice/internal/util"
	"apprentice/pkg/permissions"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/tasks"
)

// authorization
var getAllowancesAllowed []string = []string{"r:apprentice:allowances:*"}
var postAllowancesAllowed []string = []string{"w:apprentice:allowances:*"}

type AllowancesHandler interface {
	// HandleAllowances handles the request to get all allowances and to create a new allowance account via post
	HandleAllowances(w http.ResponseWriter, r *http.Request)

	// HandleAllowance handles the request to get a specific allowance account
	HandleAllowance(w http.ResponseWriter, r *http.Request)
}

// NewAllowancesHandler creates a new AllowancesHandler interface, returning a pointer to the concrete implementation
func NewAllowancesHandler(s Service, p permissions.Service, s2s, iam jwt.Verifier, tkn provider.S2sTokenProvider, identity connect.S2sCaller) AllowancesHandler {
	return &allowancesHandler{
		service:    s,
		permission: p,
		s2s:        s2s,
		iam:        iam,
		tkn:        tkn,
		identity:   identity,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
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
	identity   connect.S2sCaller

	logger *slog.Logger
}

// HandleAllowances handles the request to get all allowances and to create a new allowance account via post
func (h *allowancesHandler) HandleAllowances(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGetAll(w, r)
		return
	case http.MethodPost:
		h.handleCreate(w, r)
		return
	default:
		h.logger.Error("only GET and POST requests are allowed to /allowances endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET and POST requests are allowed to /allowances endpoint",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *allowancesHandler) HandleAllowance(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGetAllownace(w, r)
		return
	case http.MethodPost:
		h.handleUpdateAllowance(w, r)
		return
	default:
		h.logger.Error("only GET and POST requests are allowed to /allowances/{slug} endpoint")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET requests are allowed to /allowances/{slug} endpoint",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetAll handles the GET request to get all allowances
func (h *allowancesHandler) handleGetAll(w http.ResponseWriter, r *http.Request) {

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(getAllowancesAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	jot, err := h.iam.BuildAuthorized(getAllowancesAllowed, accessToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowances handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get permissions
	pm, _, err := h.permission.GetPermissions(jot.Claims.Subject)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowances handler failed to get permissions: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permissions",
		}
		e.SendJsonErr(w)
		return
	}

	// check permissions
	if _, ok := pm["payroll"]; !ok {
		errMsg := fmt.Sprintf("%s to view /allowances", exo.UserForbidden)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// get all allowances
	allowances, err := h.service.GetAllowances()
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowances get-handler failed to get all allowances: %s", err.Error()))
		h.service.HandleAllowanceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(allowances); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances get-handler failed to json encode response: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *allowancesHandler) handleGetAllownace(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(getAllowancesAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/allowance handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	jot, err := h.iam.BuildAuthorized(getAllowancesAllowed, accessToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowance handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get permissions
	pm, _, err := h.permission.GetPermissions(jot.Claims.Subject)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowances handler failed to get permissions: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get permissions",
		}
		e.SendJsonErr(w)
		return
	}

	// quick check permissions
	_, isPayroll := pm["payroll"]
	_, isRemittee := pm["remittee"]

	if !isPayroll && !isRemittee {
		errMsg := fmt.Sprintf("%s to view /allowances/{slug}", exo.UserForbidden)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// get allowance
	allowance, err := h.service.GetBySlug(slug)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowances get-handler failed to get allowance: %s", err.Error()))
		h.service.HandleAllowanceError(w, err)
		return
	}

	// must either be payroll or own the allowance account to view it.
	if !isPayroll && jot.Claims.Subject != allowance.Username {
		if !isRemittee {
			errMsg := fmt.Sprintf("%s to view /allowances/%s", exo.UserForbidden, slug)
			h.logger.Error(errMsg)
			e := connect.ErrorHttp{
				StatusCode: http.StatusForbidden,
				Message:    errMsg,
			}
			e.SendJsonErr(w)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances/%s get-handler failed to json encode response: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleCreate handles the POST request to create a new allowance account
func (h *allowancesHandler) handleCreate(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(postAllowancesAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authorized, err := h.iam.BuildAuthorized(postAllowancesAllowed, accessToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowances handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// decode request body
	var cmd CreateAllowanceCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances post-handler failed to decode request body: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances post-handler failed to validate request body: %s", err.Error()))
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
	iamToken, err := h.tkn.GetServiceToken(util.ServiceIdentity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowances post-handler failed to get service token: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed create allowance account due to internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// get user info from identity service --> service endpoint --> /s2s/users/{slug}
	var user profile.User
	if err := h.identity.GetServiceData(fmt.Sprintf("/s2s/users/%s", cmd.Slug), iamToken, "", &user); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances post-handler failed to get user info: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed create allowance account due to internal service error",
		}
		e.SendJsonErr(w)
		return
	}

	// validate submitted email matches the user's email from the identity service
	if strings.TrimSpace(cmd.Username) != user.Username {
		h.logger.Error("submitted username %s does not match user account username %s", cmd.Username, user.Username)
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "submitted email does not match user account email",
		}
		e.SendJsonErr(w)
		return
	}

	// validate user dob is on file
	if user.BirthDate == "" {
		h.logger.Error(fmt.Sprintf("failed to create allowance account because user account %s does not have a birth date on file", user.Username))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "failed to create allowance account because user account does not have a birth date on file",
		}
		e.SendJsonErr(w)
		return
	}

	// validatte submitted dob matches the user's dob from the identity service
	if strings.TrimSpace(cmd.BirthDate) != user.BirthDate {
		h.logger.Error(fmt.Sprintf("submitted birth date %s does not match user account %s birth date %s", cmd.BirthDate, user.Username, user.BirthDate))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "submitted birth date does not match user account birth date",
		}
		e.SendJsonErr(w)
		return
	}

	// validate account is not disabled
	if !user.Enabled {
		h.logger.Error(fmt.Sprintf("failed to create allowance account because user account %s is disabled", user.Username))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "failed to create allowance account because user account is disabled",
		}
		e.SendJsonErr(w)
		return
	}

	// validate account is not locked
	if user.AccountLocked {
		h.logger.Error(fmt.Sprintf("failed to create allowance account because user account %s is locked", user.Username))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "failed to create allowance account because user account is locked",
		}
		e.SendJsonErr(w)
		return
	}

	// validate account is not expired
	if user.AccountExpired {
		h.logger.Error(fmt.Sprintf("failed to create allowance account because user account %s is expired", user.Username))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    "failed to create allowance account because user account is expired",
		}
		e.SendJsonErr(w)
		return
	}

	// create allowance account
	// account creation will check if an account already exists for the user
	// and return an error if it does
	allowance, err := h.service.CreateAllowance(cmd.Username)
	if err != nil {
		h.service.HandleAllowanceError(w, err)
		return
	}

	// audit log
	h.logger.Info(fmt.Sprintf("allowance account created for user %s by %s", cmd.Username, authorized.Claims.Subject))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(allowance); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances post-handler failed to json encode response: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

func (h *allowancesHandler) handleUpdateAllowance(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(postAllowancesAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/allowance handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authorized, err := h.iam.BuildAuthorized(postAllowancesAllowed, accessToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowance handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get the url slug from the request
	slug, err := connect.GetValidSlug(r)
	if err != nil {
		h.logger.Error(fmt.Sprintf("failed to get valid slug from request: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "invalid service client slug",
		}
		e.SendJsonErr(w)
		return
	}

	// decode request body
	var cmd tasks.UpdateAllowanceCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances/%s put-handler failed to decode request body: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances/%s put-handler failed to validate request body: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// get allowance by slug to check update values for business logic issues
	allowance, err := h.service.GetBySlug(slug)
	if err != nil {
		h.service.HandleAllowanceError(w, err)
		return
	}

	// validate update values --> business logic
	if err := h.service.ValidateUpdate(cmd, *allowance); err != nil {
		h.logger.Error(fmt.Sprintf("failed to update %s's allowance account: %s", allowance.Username, err.Error()))
		h.service.HandleAllowanceError(w, err)
		return
	}

	// prepare updated allowance
	// used as return object if update successful
	updated := tasks.Allowance{
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
		h.service.HandleAllowanceError(w, err)
		return
	}

	// audit log
	if cmd.Credit > 0 {
		h.logger.Info(fmt.Sprintf("%s's allowance account successfully credited $%.2f by %s", allowance.Username, float64(cmd.Credit)/float64(100), authorized.Claims.Subject))
	}

	if cmd.Debit > 0 {
		h.logger.Info(fmt.Sprintf("%s's allowance account successfully debited $%.2f by %s", allowance.Username, float64(cmd.Debit)/float64(100), authorized.Claims.Subject))
	}

	if updated.Balance != allowance.Balance {
		h.logger.Info(fmt.Sprintf("%s's allowance account successfully updated by %s to new balance of $%.2f", allowance.Username, authorized.Claims.Subject, float64(updated.Balance)/float64(100)))
	}

	if updated.IsArchived != allowance.IsArchived {
		h.logger.Info(fmt.Sprintf("%s's allowance account archived status updated to '%t' by %s", allowance.Username, updated.IsArchived, authorized.Claims.Subject))
	}

	if updated.IsActive != allowance.IsActive {
		h.logger.Info(fmt.Sprintf("%s's allowance account active status updated to '%t' by %s", allowance.Username, updated.IsActive, authorized.Claims.Subject))
	}

	if updated.IsCalculated != allowance.IsCalculated {
		h.logger.Info(fmt.Sprintf("%s's allowance account calculated status updated to '%t' by %s", allowance.Username, updated.IsCalculated, authorized.Claims.Subject))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(updated); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances/%s post-handler failed to json encode response: %s", slug, err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}
