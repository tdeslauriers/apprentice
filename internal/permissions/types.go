package permissions

import (
	"github.com/tdeslauriers/apprentice/internal/util"
	"github.com/tdeslauriers/carapace/pkg/data"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
)

// serivces that are allowed to create permission records in this service, ie, only this service.
var AllowedServices = map[string]struct{}{
	util.ServiceApprentice: {},
}

// Service is a top level interface for the permissions package acts as a service aggregator
type Service interface {
	exo.Service
	AllowancePermissionsService
}

// NewService creates a new Service interface
// and returns a pointer to a concrete implementations of the interfaces
func NewService(a AllowancePermissionsService, p exo.Service) Service {
	return &service{
		// Service:                     exo.NewService(sql, i, c, allowedServices),
		// AllowancePermissionsService: NewAllowancePermissionsService(sql, i, c),
		Service:                     p,
		AllowancePermissionsService: a,
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface
// It aggregates the permissions services together
type service struct {
	exo.Service
	AllowancePermissionsService
}

// AllowancePermissionRecord is a model representing an allowance permission xref record
type AllowancePermissionRecord struct {
	Id           int             `db:"id"`
	AllowanceId  string          `db:"allowance_uuid"`
	PermissionId string          `db:"permission_uuid"`
	CreatedAt    data.CustomTime `db:"created_at"`
}
