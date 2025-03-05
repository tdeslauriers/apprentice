package allowances

import (
	"apprentice/internal/util"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

type AllowanceErrorService interface {
	// HandleAllowanceError handles the error response for allowance functions
	HandleAllowanceError(w http.ResponseWriter, err error)
}

// NewAllowanceErrorService creates a new AllowanceErrorService interface, returning a pointer to the concrete implementation
func NewAllowanceErrorService() AllowanceErrorService {
	return &allowanceErrorService{
		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageAllowances)).
			With(slog.String(util.ComponentKey, util.ComponentAllowances)),
	}
}

var _ AllowanceErrorService = (*allowanceErrorService)(nil)

// allowanceErrorService is the concrete implementation of the AllowanceErrorService interface
type allowanceErrorService struct {
	logger *slog.Logger
}

// HandleAllowanceError handles the error response for allowance functions
func (s *allowanceErrorService) HandleAllowanceError(w http.ResponseWriter, err error) {

	switch {
	case strings.Contains(err.Error(), ErrAccountExists):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusConflict,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	case strings.Contains(err.Error(), ErrInvalidUsername):
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	default:
		s.logger.Error(err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}
