package allowances

import (
	"apprentice/internal/util"
	"apprentice/pkg/permissions"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
)

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
		h.logger.Error(fmt.Sprintf("/allowance account handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// TODO: add permissions check back when permission ui is implemented.
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
