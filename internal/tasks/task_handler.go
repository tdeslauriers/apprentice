package tasks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/tdeslauriers/apprentice/internal/allowances"
	"github.com/tdeslauriers/apprentice/internal/permissions"
	"github.com/tdeslauriers/apprentice/internal/util"
	api "github.com/tdeslauriers/apprentice/pkg/api/tasks"
	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/shaw/pkg/api/user"
)

var readTasksAllowed = []string{"r:apprentice:*", "r:apprentice:tasks:*"}
var writeTasksAllowed = []string{"w:apprentice:*", "w:apprentice:tasks:*"}

// Handler is an interface to handle task service functionality
// It is used to handle HTTP requests and responses
type Handler interface {
	// HandleTasks is a method to handle calls to the /tasks endpoint
	HandleTasks(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new Handler interface, returning a pointer to the concrete implementation
func NewHandler(
	s Service,
	a allowances.Service,
	p permissions.Service,
	s2s jwt.Verifier,
	iam jwt.Verifier,
	tkn provider.S2sTokenProvider,
	c *connect.S2sCaller,
) Handler {

	return &handler{
		svc:         s,
		allowance:   a,
		permissions: p,
		s2s:         s2s,
		iam:         iam,
		tkn:         tkn,
		identity:    c,

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageTasks)).
			With(slog.String(util.ComponentKey, util.ComponentTasks)),
	}
}

var _ Handler = (*handler)(nil)

// handler is the concrete implementation of the Handler interface
type handler struct {
	svc         Service
	allowance   allowances.Service
	permissions permissions.Service
	s2s         jwt.Verifier
	iam         jwt.Verifier
	tkn         provider.S2sTokenProvider
	identity    *connect.S2sCaller

	logger *slog.Logger
}

// HandleTasks is a concrete implementation of the HandleTasks method in the Handler interface
func (h *handler) HandleTasks(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.getTasks(w, r)
		return
	case http.MethodPatch:
		h.updateTaskStatus(w, r)
		return
	default:
		// get telemetry from request
		tel := connect.ObtainTelemetry(r, h.logger)
		log := h.logger.With(tel.TelemetryFields()...)

		log.Error(fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path))
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    fmt.Sprintf("unsupported method %s for endpoint %s", r.Method, r.URL.Path),
		}
		e.SendJsonErr(w)
		return
	}
}

// getTasks is a concrete implementation of the HandleTasks GET functionality.
// It handles query params and returns a list of tasks.   In addition to jwt authorization,
// it also checks the fine grain permissions for the user.
func (h *handler) getTasks(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// add telemetry to context for downstream calls + service functions
	ctx := context.WithValue(r.Context(), connect.TelemetryKey, tel)

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(readTasksAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	// need subject to determine fine grain permissions
	iamToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(readTasksAllowed, iamToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// get query params
	params := r.URL.Query()
	if len(params) > 0 {
		// validate query params
		if err := ValidateQueryParams(params); err != nil {
			log.Error("invalid query params", "err", err.Error())
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnprocessableEntity,
				Message:    fmt.Sprintf("invalid query params: %v", err),
			}
			e.SendJsonErr(w)
			return
		}
	}

	// get fine grain permissions map for query building
	ps, _, err := h.permissions.GetAllowancePermissions(authedUser.Claims.Subject)
	if err != nil {
		log.Error("failed to get user's permissions", "err", err.Error())
		// this is not a 401 or 403, just fetching.  Permission correctness (if applicable) is checked below
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to get user's permissions: %v", err),
		}
		e.SendJsonErr(w)
		return
	}

	// assignees require a permission check for 'all' or user uuids.
	// all allowance users can query "me", but additional permissions are needed for everything else.
	if params.Has("assignee") && params.Get("assignee") != "me" {
		if _, ok := ps[util.PermissionPayroll]; !ok {
			log.Error("failed to get assignees",
				"err", "user does not have correct permissions to get these assignees")
			e := connect.ErrorHttp{
				StatusCode: http.StatusForbidden,
				Message:    "user does not have correct permissions to get these assignees",
			}
			e.SendJsonErr(w)
			return
		}
	}

	// sebd params and permissions to task service for user in query building
	records, err := h.svc.GetTasks(authedUser.Claims.Subject, params, ps)
	if err != nil {
		log.Error("failed to get tasks", "err", err.Error())
		h.svc.HandleServiceError(w, err)
		return
	}

	// get all assignees from the database to hiydrate the task list
	// get identity service token
	identityS2sToken, err := h.tkn.GetServiceToken(ctx, util.ServiceIdentity)
	if err != nil {
		log.Error("failed to get identity service s2s token", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// call identity service to get all users with the <r/w>:apprentice:task:* scopes
	encoded := url.QueryEscape("r:apprentice:tasks:* w:apprentice:tasks:*")
	assignees, err := connect.GetServiceData[[]user.User](
		ctx,
		h.identity,
		fmt.Sprintf("/s2s/users/groups?scopes=%s", encoded),
		identityS2sToken,
		"",
	)
	if err != nil {
		log.Error("failed to get users from identity service", "err", err.Error())
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// make assignee map for lookup
	assigneeMap := make(map[string]user.User, len(assignees))
	for _, a := range assignees {
		assigneeMap[a.Username] = a
	}

	// prepare task records to return
	tasks := make([]api.Task, len(records))
	for i, r := range records {

		// make sure assignee exists in the map
		if _, ok := assigneeMap[r.Username]; !ok {
			log.Error("failed to find assignee in allowance users")
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "failed to find assignee %s in allowance users",
			}
			e.SendJsonErr(w)
			return
		}

		tasks[i] = api.Task{
			Id:             r.Id,
			Name:           r.Name,
			Description:    r.Description,
			Cadence:        r.Cadence,
			Category:       r.Category,
			CreatedAt:      r.CreatedAt,
			IsComplete:     r.IsComplete,
			CompletedAt:    r.CompletedAt,
			IsSatisfactory: r.IsSatisfactory,
			IsProactive:    r.IsProactive,
			TaskSlug:       r.TaskSlug,
			IsArchived:     r.IsArchived,
			AllowanceSlug:  r.AllowanceSlug,
			Assignee:       assigneeMap[r.Username],
		}
	}

	// send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(tasks); err != nil {
		log.Error("failed to json encode response", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}

// updateTaskStatus is a concrete implementation of the HandleTasks POST functionality.
// It handles updating a task record status.
func (h *handler) updateTaskStatus(w http.ResponseWriter, r *http.Request) {

	// get telemetry from request
	tel := connect.ObtainTelemetry(r, h.logger)
	log := h.logger.With(tel.TelemetryFields()...)

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	authedSvc, err := h.s2s.BuildAuthorized(writeTasksAllowed, svcToken)
	if err != nil {
		log.Error("failed to authorize s2s token", "err", err.Error())
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}
	log = log.With("requesting_service", authedSvc.Claims.Subject)

	// validate iam token
	// need the princpal to determine fine grain permissions
	iamToken := r.Header.Get("Authorization")
	authedUser, err := h.iam.BuildAuthorized(writeTasksAllowed, iamToken)
	if err != nil {
		log.Error("failed to authorize iam token", "err", err.Error())
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}
	log = log.With("actor", authedUser.Claims.Subject)

	// decode request body
	var cmd api.TaskStatusCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		log.Error(fmt.Sprintf("failed to decode request body: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    "failed to decode request body",
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		log.Error("failed to validate request body", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    err.Error(),
		}
		e.SendJsonErr(w)
		return
	}

	var (
		wg        sync.WaitGroup
		errChan   = make(chan error, 2)
		psMapChan = make(chan map[string]exo.PermissionRecord, 1)
		taskChan  = make(chan api.TaskData, 1)
	)

	// get fine grain permissions map for query building
	wg.Add(1)
	go func() {
		defer wg.Done()

		ps, _, err := h.permissions.GetAllowancePermissions(authedUser.Claims.Subject)
		if err != nil {
			log.Error("failed to get user's permissions", "err", err.Error())
			errChan <- err
			return
		}
		psMapChan <- ps
	}()

	// get the task recored with allowance
	wg.Add(1)
	go func() {
		defer wg.Done()
		// get t record
		t, err := h.svc.GetTask(cmd.TaskSlug)
		if err != nil {
			errChan <- err
			return
		}
		if t == nil {
			errChan <- err
			return
		}
		taskChan <- *t
	}()

	wg.Wait()
	close(errChan)
	close(psMapChan)
	close(taskChan)

	// check for errors
	if len(errChan) > 0 {
		var errs []error
		for err := range errChan {
			errs = append(errs, err)
		}
		log.Error(fmt.Sprintf("failed to get task slug %s", cmd.TaskSlug), "err", errors.Join(errs...))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to get task",
		}
		e.SendJsonErr(w)
		return
	}

	psMap := <-psMapChan
	task := <-taskChan

	// check for permissions
	_, isPayroll := psMap[util.PermissionPayroll]
	_, isRemittee := psMap[util.PermissionRemittee]

	// handle permission errors
	if !isPayroll && !isRemittee {
		log.Error(fmt.Sprintf("failed to update task slug %s", cmd.TaskSlug),
			"err", "user does not have correct permissions to update this task")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "user does not have correct permissions to update this task",
		}
		e.SendJsonErr(w)
		return
	}

	if !isPayroll && (cmd.Status == "is_satisfactory" || cmd.Status == "is_proactive") {
		log.Error(fmt.Sprintf("failed to update task slug %s status: %s", cmd.TaskSlug, cmd.Status),
			"err", "user does not have correct permissions to update this status")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    "user does not have correct permissions to update this status",
		}
		e.SendJsonErr(w)
		return
	}

	if !isPayroll && (task.Username != authedUser.Claims.Subject || !isRemittee) {
		errMsg := fmt.Sprintf("%s to update task (slug %s): %s", exo.UserForbidden, cmd.TaskSlug, authedUser.Claims.Subject)
		log.Error(fmt.Sprintf("failed to update task slug %s", cmd.TaskSlug),
			"err", "user does not have correct permissions to update this task")
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// prepare record by setting all fields to the current values
	record := TaskRecord{
		Id:             task.Id,
		CreatedAt:      task.CreatedAt,
		IsComplete:     task.IsComplete,
		IsSatisfactory: task.IsSatisfactory,
		IsProactive:    task.IsProactive,
		Slug:           task.TaskSlug,
		IsArchived:     task.IsArchived,
	}

	// get complated_at time if it exists and set it
	ca, err := time.Parse("2006-01-02 15:04:05", task.CompletedAt)
	if err == nil {
		record.CompletedAt = sql.NullTime{
			Time:  ca,
			Valid: task.CompletedAt != "",
		}
	}

	// handle status updates for satisfactory and proactive
	if isPayroll {
		if cmd.Status == "is_satisfactory" {
			record.IsSatisfactory = !task.IsSatisfactory
		} else {
			record.IsSatisfactory = task.IsSatisfactory
		}

		if cmd.Status == "is_proactive" {
			record.IsProactive = !task.IsProactive
		} else {
			record.IsProactive = task.IsProactive
		}
	}

	// remittee can update their own task complete status, or payroll can update it
	if cmd.Status == "is_complete" &&
		(isPayroll || (isRemittee && task.Username == authedUser.Claims.Subject)) {

		record.IsComplete = !task.IsComplete
		if record.IsComplete {
			record.CompletedAt = sql.NullTime{
				Time:  time.Now().UTC(),
				Valid: true,
			}
		} else {
			record.CompletedAt = sql.NullTime{
				Time:  time.Time{},
				Valid: false,
			}
		}
	}

	if err := h.svc.UpdateTask(record); err != nil {
		log.Error(fmt.Sprintf("failed to update task slug %s", cmd.TaskSlug), "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to update task",
		}
		e.SendJsonErr(w)
		return
	}

	// audit trail logs
	if record.IsComplete != task.IsComplete {
		log.Info(fmt.Sprintf("task slug %s is_complete status updated to %t", task.TaskSlug, record.IsComplete))
		task.IsComplete = record.IsComplete // for return value
	}

	if record.IsSatisfactory != task.IsSatisfactory {
		log.Info(fmt.Sprintf("task slug %s is_satisfactory status updated to %t", task.TaskSlug, record.IsSatisfactory))
		task.IsSatisfactory = record.IsSatisfactory // for return value
	}

	if record.IsProactive != task.IsProactive {
		log.Info(fmt.Sprintf("task slug %s is_proactive status updated to %t", task.TaskSlug, record.IsProactive))
		task.IsProactive = record.IsProactive // for return value
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(task); err != nil {
		log.Error("failed to json encode response", "err", err.Error())
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "failed to json encode response",
		}
		e.SendJsonErr(w)
		return
	}
}
