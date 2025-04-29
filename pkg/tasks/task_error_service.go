package tasks

import (
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/connect"
)

// TaskErrorService is an interface to handle task error service functionality
type TaskErrorService interface {

	// HandleServiceError is a method to handle errors returned from the task service(s)
	HandleServiceError(w http.ResponseWriter, err error)
}

// NewTaskErrorService creates a new TaskErrorService interface, returning a pointer to the concrete implementation
func NewTaskErrorService() TaskErrorService {
	return &taskErrorService{}
}

var _ TaskErrorService = (*taskErrorService)(nil)

// taskErrorService is the concrete implementation of the TaskErrorService interface
type taskErrorService struct {
}

// HandleServiceError is a concrete implementation of the HandleServiceError method in the TaskErrorService interface
func (s *taskErrorService) HandleServiceError(w http.ResponseWriter, err error) {

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
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}
