package tasks

import (
	"apprentice/internal/util"
	"apprentice/pkg/allowances"
	"apprentice/pkg/permissions"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/jwt"
	exoPermissions "github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
	"github.com/tdeslauriers/carapace/pkg/tasks"
)

var readTasksAllowed = []string{"r:apprentice:tasks:*"}
var writeTasksAllowed = []string{"w:apprentice:tasks:*"}

// Handler is an interface to handle task service functionality
// It is used to handle HTTP requests and responses
type Handler interface {
	// HandleTasks is a method to handle calls to the /tasks endpoint
	HandleTasks(w http.ResponseWriter, r *http.Request)
}

// NewHandler creates a new Handler interface, returning a pointer to the concrete implementation
func NewHandler(s Service, a allowances.Service, p permissions.Service, s2s, iam jwt.Verifier, tkn provider.S2sTokenProvider, c connect.S2sCaller) Handler {
	return &handler{
		svc:         s,
		allowance:   a,
		permissions: p,
		s2s:         s2s,
		iam:         iam,
		tkn:         tkn,
		identity:    c,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
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
	identity    connect.S2sCaller

	logger *slog.Logger
}

// HandleTasks is a concrete implementation of the HandleTasks method in the Handler interface
func (h *handler) HandleTasks(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodGet:
		h.handleGetTasks(w, r)
		return
	case http.MethodPost:
		h.handlePostTasks(w, r)
		return
	default:
		h.logger.Error("only GET and POST method is allowed to /tasks")
		e := connect.ErrorHttp{
			StatusCode: http.StatusMethodNotAllowed,
			Message:    "only GET and POST method is allowed to /tasks",
		}
		e.SendJsonErr(w)
		return
	}
}

// handleGetTasks is a concrete implementation of the HandleTasks GET functionality.
// It handles query params and returns a list of tasks.   In addition to jwt authorization,
// it also checks the fine grain permissions for the user.
func (h *handler) handleGetTasks(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(readTasksAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to authorize s2s token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	// need subject to determine fine grain permissions
	iamToken := r.Header.Get("Authorization")
	jot, err := h.iam.BuildAuthorized(readTasksAllowed, iamToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to authorize iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// get query params
	params := r.URL.Query()
	if len(params) > 0 {
		// validate query params
		if err := tasks.ValidateQueryParams(params); err != nil {
			h.logger.Error(fmt.Sprintf("/tasks handler failed to validate query params: %v", err))
			e := connect.ErrorHttp{
				StatusCode: http.StatusUnprocessableEntity,
				Message:    fmt.Sprintf("invalid query params: %v", err),
			}
			e.SendJsonErr(w)
			return
		}
	}

	// get fine grain permissions map for query building
	ps, _, err := h.permissions.GetPermissions(jot.Claims.Subject)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to get %s's permissions: %v", jot.Claims.Subject, err))
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
		if _, ok := ps["payroll"]; !ok {
			h.logger.Error(fmt.Sprintf("user %s does not have permission to get assignees=%s", jot.Claims.Subject, params.Get("assignee")))
			e := connect.ErrorHttp{
				StatusCode: http.StatusForbidden,
				Message:    fmt.Sprintf("%s to get assignees=%s: %s", exoPermissions.UserForbidden, params.Get("assignee"), jot.Claims.Subject),
			}
			e.SendJsonErr(w)
			return
		}
	}

	// sebd params and permissions to task service for user in query building
	records, err := h.svc.GetTasks(jot.Claims.Subject, params, ps)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to get tasks: %v", err))
		h.svc.HandleServiceError(w, err)
		return
	}

	// get all assignees from the database to hiydrate the task list
	// get identity service token
	identityS2sToken, err := h.tkn.GetServiceToken(util.ServiceIdentity)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to get identity service token: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// call identity service to get all users with the <r/w>:apprentice:task:* scopes
	var assignees []profile.User
	encoded := url.QueryEscape("r:apprentice:tasks:* w:apprentice:tasks:*")
	if err := h.identity.GetServiceData(fmt.Sprintf("/s2s/users/groups?scopes=%s", encoded), identityS2sToken, "", &assignees); err != nil {
		h.logger.Error(fmt.Sprintf("/templates/assignees handler failed to get tasks service users from identity service: %v", err))
		h.identity.RespondUpstreamError(err, w)
		return
	}

	// make assignee map for lookup
	assigneeMap := make(map[string]profile.User, len(assignees))
	for _, a := range assignees {
		assigneeMap[a.Username] = a
	}

	// prepare task records to return
	ts := make([]tasks.Task, len(records))
	for i, r := range records {

		// make sure assignee exists in the map
		if _, ok := assigneeMap[r.Username]; !ok {
			h.logger.Error(fmt.Sprintf("/tasks handler failed to find assignee %s in map", r.Username))
			e := connect.ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    fmt.Sprintf("failed to find assignee %s in allowance users", r.Username),
			}
			e.SendJsonErr(w)
			return
		}

		ts[i] = tasks.Task{
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
	if err := json.NewEncoder(w).Encode(ts); err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to send json response: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}

// handlePostTasks is a concrete implementation of the HandleTasks POST functionality.
// It handles updating a task record status.
func (h *handler) handlePostTasks(w http.ResponseWriter, r *http.Request) {

	// validate s2s token
	svcToken := r.Header.Get("Service-Authorization")
	if _, err := h.s2s.BuildAuthorized(writeTasksAllowed, svcToken); err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to authorize s2s token: %v", err))
		connect.RespondAuthFailure(connect.S2s, err, w)
		return
	}

	// validate iam token
	// need the princpal to determine fine grain permissions
	iamToken := r.Header.Get("Authorization")
	jot, err := h.iam.BuildAuthorized(writeTasksAllowed, iamToken)
	if err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to authorize iam token: %v", err))
		connect.RespondAuthFailure(connect.User, err, w)
		return
	}

	// decode request body
	var cmd tasks.TaskStatusCmd
	if err := json.NewDecoder(r.Body).Decode(&cmd); err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to decode request body: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("failed to decode request body: %v", err),
		}
		e.SendJsonErr(w)
		return
	}

	// validate request body
	if err := cmd.ValidateCmd(); err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to validate request body: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    fmt.Sprintf("invalid request body: %v", err),
		}
		e.SendJsonErr(w)
		return
	}

	var (
		wg        sync.WaitGroup
		errChan   = make(chan error, 2)
		psMapChan = make(chan map[string]exoPermissions.Permission, 1)
		taskChan  = make(chan TaskRecord, 1)
	)

	// get fine grain permissions map for query building
	wg.Add(1)
	go func() {
		defer wg.Done()

		ps, _, err := h.permissions.GetPermissions(jot.Claims.Subject)
		if err != nil {
			h.logger.Error(fmt.Sprintf("/tasks handler failed to get %s's permissions: %v", jot.Claims.Subject, err))
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
		var errs []string
		for err := range errChan {
			errs = append(errs, err.Error())
		}
		errMsg := fmt.Sprintf("/task handler failed to get task (slug %s) record: %v", cmd.TaskSlug, strings.Join(errs, "; "))
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	psMap := <-psMapChan
	task := <-taskChan

	// check for permissions
	_, isPayroll := psMap["payroll"]
	_, isRemittee := psMap["remittee"]

	// handle permission errors
	if !isPayroll && !isRemittee {
		errMsg := fmt.Sprintf("%s to update task slug (%s): %s", exoPermissions.UserForbidden, cmd.TaskSlug, jot.Claims.Subject)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	if !isPayroll && (cmd.Status == "is_satisfactory" || cmd.Status == "is_proactive") {
		errMsg := fmt.Sprintf("%s to update task (slug %s) status %s: %s", exoPermissions.UserForbidden, cmd.TaskSlug, cmd.Status, jot.Claims.Subject)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	if !isPayroll && (task.Username != jot.Claims.Subject || !isRemittee) {
		errMsg := fmt.Sprintf("%s to update task (slug %s): %s", exoPermissions.UserForbidden, cmd.TaskSlug, jot.Claims.Subject)
		h.logger.Error(errMsg)
		e := connect.ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    errMsg,
		}
		e.SendJsonErr(w)
		return
	}

	// prepare record by setting all fields to the current values
	record := Task{
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
		(isPayroll || (isRemittee && task.Username == jot.Claims.Subject)) {

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
		h.logger.Error(fmt.Sprintf("/tasks handler failed to update task (slug %s): %v", task.TaskSlug, err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("failed to update task: %v", err),
		}
		e.SendJsonErr(w)
		return
	}

	// audit trail logs
	if record.IsComplete != task.IsComplete {
		h.logger.Info(fmt.Sprintf("task (slug %s) is_complete status updated to %t by %s", task.TaskSlug, record.IsComplete, jot.Claims.Subject))
		task.IsComplete = record.IsComplete // for return value
	}

	if record.IsSatisfactory != task.IsSatisfactory {
		h.logger.Info(fmt.Sprintf("task (slug %s) is_satisfactory status updated to %t by %s", task.TaskSlug, record.IsSatisfactory, jot.Claims.Subject))
		task.IsSatisfactory = record.IsSatisfactory // for return value
	}

	if record.IsProactive != task.IsProactive {
		h.logger.Info(fmt.Sprintf("task (slug %s) is_proactive status updated to %t by %s", task.TaskSlug, record.IsProactive, jot.Claims.Subject))
		task.IsProactive = record.IsProactive // for return value
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(task); err != nil {
		h.logger.Error(fmt.Sprintf("/tasks handler failed to send json response: %v", err))
		e := connect.ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}
}
