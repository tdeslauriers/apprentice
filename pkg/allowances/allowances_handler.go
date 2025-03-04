package allowances

import (
	"apprentice/internal/util"
	"log/slog"
	"net/http"

	"github.com/tdeslauriers/carapace/pkg/jwt"
)

type AllowancesHandler interface {
	// HandleAllowances handles the request to get all allowances and to create a new allowance account via post
	HandleAllowances(w http.ResponseWriter, r *http.Request)
}

// NewAllowancesHandler creates a new AllowancesHandler interface, returning a pointer to the concrete implementation
func NewAllowancesHandler(s Service, s2s, iam jwt.Verifier) AllowancesHandler {
	return &allowancesHandler{
		service: s,
		s2s:     s2s,
		iam:     iam,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageAllowances)).
			With(slog.String(util.ComponentKey, util.ComponentAllowances)),
	}
}

var _ AllowancesHandler = (*allowancesHandler)(nil)

// allowancesHandler is the concrete implementation of the AllowancesHandler interface
type allowancesHandler struct {
	service Service
	s2s     jwt.Verifier
	iam     jwt.Verifier

	logger *slog.Logger
}

// HandleAllowances handles the request to get all allowances and to create a new allowance account via post
func (h *allowancesHandler) HandleAllowances(w http.ResponseWriter, r *http.Request) {
}
