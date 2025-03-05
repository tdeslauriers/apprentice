package allowances

import (
	"apprentice/internal/util"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// authorization
var getAllowancesAllowed []string = []string{"r:apprentice:allowances:*"}
var postAllowancesAllowed []string = []string{"w:apprentice:allowances:*"}

type AllowancesHandler interface {
	// HandleAllowances handles the request to get all allowances and to create a new allowance account via post
	HandleAllowances(w http.ResponseWriter, r *http.Request)
}

// NewAllowancesHandler creates a new AllowancesHandler interface, returning a pointer to the concrete implementation
func NewAllowancesHandler(s Service, s2s, iam jwt.Verifier, tkn provider.S2sTokenProvider, identity connect.S2sCaller) AllowancesHandler {
	return &allowancesHandler{
		service:  s,
		s2s:      s2s,
		iam:      iam,
		tkn:      tkn,
		identity: identity,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageAllowances)).
			With(slog.String(util.ComponentKey, util.ComponentAllowances)),
	}
}

var _ AllowancesHandler = (*allowancesHandler)(nil)

// allowancesHandler is the concrete implementation of the AllowancesHandler interface
type allowancesHandler struct {
	service  Service
	s2s      jwt.Verifier
	iam      jwt.Verifier
	tkn      provider.S2sTokenProvider
	identity connect.S2sCaller

	logger *slog.Logger
}

// HandleAllowances handles the request to get all allowances and to create a new allowance account via post
func (h *allowancesHandler) HandleAllowances(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		// get all allowances
		return
	case http.MethodPost:
		h.handlePost(w, r)
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

// handlePost handles the POST request to create a new allowance account
func (h *allowancesHandler) handlePost(w http.ResponseWriter, r *http.Request) {

	// validate s2stoken
	svcToken := r.Header.Get("Service-Authorization")
	if authorized, err := h.s2s.IsAuthorized(postAllowancesAllowed, svcToken); !authorized {
		h.logger.Error(fmt.Sprintf("/allowances/ post-handler failed to authorize service token: %s", err.Error()))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	accessToken := r.Header.Get("Authorization")
	if authorized, err := h.iam.IsAuthorized(postAllowancesAllowed, accessToken); !authorized {
		h.logger.Error(fmt.Sprintf("/allowances post-handler failed to authorize iam token: %s", err.Error()))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// needed for the audit log (who is creating the account)
	jot, err := jwt.BuildFromToken(strings.TrimPrefix(accessToken, "Bearer "))
	if err != nil {
		h.logger.Error(fmt.Sprintf("/allowances post-handler failed to parse jwt token: %s", err.Error()))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to parse jwt token",
		}
		e.SendJsonErr(w)
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
	h.logger.Info(fmt.Sprintf("allowance account created for user %s by %s", cmd.Username, jot.Claims.Subject))

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
