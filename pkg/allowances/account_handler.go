package allowances

import (
	"apprentice/internal/util"
	"apprentice/pkg/permissions"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/tasks"
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
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
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

	// check the method
	switch r.Method {
	case http.MethodGet:
		h.handleGetAccount(w, r)
		return
	case http.MethodPost:
		h.handleUpdateAccount(w, r)
		return
	default:
		errMsg := fmt.Sprintf("unsupported method %s for /allowance account", r.Method)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetAccount is the concrete implementation of the method to retreive an allowance account
func (h *accountHandler) handleGetAccount(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(getAccountAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/allowance handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	jot, err := h.iam.BuildAuthorized(getAccountAllowed, accessToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowance account handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// TODO: add remittee permissions check back when permission ui is implemented.
	// get permissions
	// pm, _, err := h.permissions.GetPermissions(jot.Claims.Subject)
	// if err != nil {
	// 	h.logger.Error(fmt.Sprintf("/allowance account handler failed to get permissions: %s", err.Error()))
	// 	e := connect.ErrorHttp{
	// 		StatusCode: http.StatusInternalServerError,
	// 		Message:    "failed to get permissions",
	// 	}
	// 	e.SendJsonErr(w)
	// 	return
	// }

	// // quick check of permissions
	// _, isRemittee := pm["remittee"]

	// if !isRemittee {
	// 	errMsg := fmt.Sprintf("%s to view allowance account: %s", exo.UserForbidden, jot.Claims.Subject)
	// 	h.logger.Error(errMsg)
	// 	e := connect.ErrorHttp{
	// 		StatusCode: http.StatusForbidden,
	// 		Message:    errMsg,
	// 	}
	// 	e.SendJsonErr(w)
	// 	return
	// }

	// get the remittee
	a, err := h.service.GetByUser(jot.Claims.Subject)
	if err != nil {
		errMsg := fmt.Sprintf("/allowance account handler failed to get remittee: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(a); err != nil {
		errMsg := fmt.Sprintf("/allowance account handler failed to encode remittee: %s", err.Error())
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}
}

// handleUpdateAccount is the concrete implementation of the method to update a user's specfic account
func (h *accountHandler) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(postAccountAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/allowance handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	authorized, err := h.iam.BuildAuthorized(postAccountAllowed, accessToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowance handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// decode request body
	var cmd tasks.UpdateAllowanceCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("/allowance put-handler failed to decode request body: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("/allowances/%s put-handler failed to validate request body:", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	// make two calls to db concurrently:
	// permissions and allowance account lookup
	var (
		wg    sync.WaitGroup
		aCh   = make(chan *tasks.Allowance, 1)
		pCh   = make(chan map[string]exo.Permission, 1)
		errCh = make(chan error, 1)
	)

	// get permissions
	wg.Add(1)
	go func() {
		defer wg.Done()

		p, _, err := h.permissions.GetPermissions(authorized.Claims.Subject)
		if err != nil {
			errCh <- err
			return
		}
		pCh <- p
	}()

	// get allowance
	wg.Add(1)
	go func() {
		defer wg.Done()

		a, err := h.service.GetByUser(authorized.Claims.Subject)
		if err != nil {
			errCh <- err
			return
		}
		aCh <- a
	}()

	wg.Wait()
	close(aCh)
	close(pCh)
	close(errCh)

	// check for errors
	if len(errCh) > 0 {
		errs := make([]string, 0, len(errCh))
		for err := range errCh {
			errs = append(errs, err.Error())
		}
		errMsg := fmt.Sprintf("/account handler failed to lookup record(s): %s", strings.Join(errs, "; "))
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	allowance := <-aCh
	pm := <-pCh

	// quick check permissions
	_, isPayroll := pm["payroll"]
	_, isRemittee := pm["remittee"]

	// if the user is not a payroll or remittee, return forbidden
	if !isPayroll && !isRemittee {
		errMsg := fmt.Sprintf("%s to update allowance account: %s", exo.UserForbidden, authorized.Claims.Subject)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// NOTE: at this time, remitees cannot update their own accounts at all
	// this may change.
	if !isPayroll {
		errMsg := fmt.Sprintf("%s to update allowance account: %s", exo.UserForbidden, authorized.Claims.Subject)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
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
		h.logger.Error(fmt.Sprintf("/allowances/%s post-handler failed to json encode response: ", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}
