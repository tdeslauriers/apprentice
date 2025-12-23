package templates

import (
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

// TemplateService is an interface to abstract away error handling for template service(s) functionality
type TemplateErrorService interface {

	// HandleServiceError is a method to handle errors returned from the template service(s)
	HandleServiceError(w http.ResponseWriter, err error)
}

// NewTemplateErrorService creates a new TemplateErrorService interface, returning a pointer to the concrete implementation
func NewTemplateErrorService() TemplateErrorService {
	return &templateErrorService{}
}

var _ TemplateErrorService = (*templateErrorService)(nil)

// templateErrorService is the concrete implementation of the TemplateErrorService interface
type templateErrorService struct {
}

// HandleServiceError is a concrete implementation of the HandleServiceError method in the TemplateErrorService interface
func (s *templateErrorService) HandleServiceError(w http.ResponseWriter, err error) {

	switch {
	case strings.Contains(err.Error(), "invalid"):
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	default:
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}
}
