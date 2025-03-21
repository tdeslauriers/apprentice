package templates

import (
	"apprentice/internal/util"
	"log/slog"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// Service is an interface to handle template service functionality
type Service interface{}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql data.SqlRepository) Service {
	return &templateService{
		db: sql,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageTemplates)).
			With(slog.String(util.ComponentKey, util.ComponentTemplates)),
	}
}

var _ Service = (*templateService)(nil)

// service is the concrete implementation of the Service interface
type templateService struct {
	db data.SqlRepository

	logger *slog.Logger
}
