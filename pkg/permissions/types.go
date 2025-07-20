package permissions

import (
	"github.com/tdeslauriers/carapace/pkg/data"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
)

// Service is a top level interface for the permissions package acts as a service aggregator
type Service interface {
	exo.Service
	AllowancePermissionsService
}

// NewService creates a new Service interface
// and returns a pointer to a concrete implementations of the interfaces
func NewService(sql data.SqlRepository, i data.Indexer, c data.Cryptor) Service {
	return &service{
		Service:                     exo.NewService(sql, i, c),
		AllowancePermissionsService: NewAllowancePermissionsService(sql, i, c),
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
