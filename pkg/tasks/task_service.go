package tasks

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/apprentice/internal/util"
	"github.com/tdeslauriers/apprentice/pkg/allowances"
	"github.com/tdeslauriers/carapace/pkg/data"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
)

// TaskService is an interface to handle task service functionality
type TaskService interface {

	// GetTasks retrieves all task records from the database that an allowance user has
	// permission to access based on query parameters if they exist
	// Note: this is meant to be a Get All Tasks function and will default to returning all tasks (based on permissions)
	// username (should come from a valid source like jwt subject) needed if permissions do not
	// allow getting all tasks: it will filter for just that user's tasks
	GetTasks(username string, paramas url.Values, permissions map[string]exo.PermissionRecord) ([]TaskData, error)

	// GetTask retrieves a single task record from the database including its template data and allowance username + slug
	GetTask(slug string) (*TaskData, error)

	// CreateTask creates a new task record in the database
	CreateTask() (*TaskRecord, error)

	// CreateAllowanceXref creates a new allowance-task xref record in the database
	CreateAllowanceXref(t *TaskRecord, a *allowances.Allowance) (*TaskAllowanceXref, error)

	// UpdateTask updates a task record in the database
	UpdateTask(t TaskRecord) error
}

// NewTaskService creates a new TaskService interface, returning a pointer to the concrete implementation
func NewTaskService(sql *sql.DB, i data.Indexer, c data.Cryptor) TaskService {
	return &taskService{
		db:      NewTaskRepository(sql, i),
		indexer: i,
		cryptor: c,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageTasks)).
			With(slog.String(util.ComponentKey, util.ComponentTasks)),
	}
}

var _ TaskService = (*taskService)(nil)

// taskService is the concrete implementation of the TaskService interface
type taskService struct {
	db      TaskRepository
	indexer data.Indexer
	cryptor data.Cryptor

	logger *slog.Logger
}

// GetTasks is a concrete implementation of the GetTasks method in the TaskService interface
// internally, it uses a query builder to build the query based on the parameters and permissions passed in
func (s *taskService) GetTasks(
	username string,
	params url.Values,
	permissions map[string]exo.PermissionRecord,
) ([]TaskData, error) {

	// find tasks in database that match the url params and permissions
	tasks, err := s.db.FindTasksByParams(username, params, permissions)
	if err != nil {
		return nil, fmt.Errorf("failed to select task records: %v", err)
	}

	// decrypt usernames
	var (
		taskUserMutex      sync.Mutex
		taskAllowanceMutex sync.Mutex
		userMutex          sync.Mutex
		allowanceMutex     sync.Mutex
		wg                 sync.WaitGroup

		// so we dont have to repeat the same decryption
		// key is encrypted username/allowance slug, value is decrypted username/allowance slug
		usernameCache  = make(map[string]string)
		allowanceCache = make(map[string]string)

		errChan = make(chan error, len(tasks))
	)

	for i := range tasks {

		// decrypted username
		wg.Add(1)
		go func(task *TaskData, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			// check if the username is already in the cache
			userMutex.Lock()
			if username, ok := usernameCache[task.Username]; ok {
				userMutex.Unlock()

				// update the task with the decrypted username
				taskUserMutex.Lock()
				task.Username = username
				taskUserMutex.Unlock()
				return
			}
			userMutex.Unlock()

			// if not, decrypt the username
			decrypted, err := s.cryptor.DecryptServiceData(task.Username)
			if err != nil {
				errChan <- fmt.Errorf("failed to decrypt username %s: %v", task.Username, err)
				return
			}
			// update the cache of decrypted usernames
			userMutex.Lock()
			usernameCache[task.Username] = string(decrypted)
			userMutex.Unlock()

			// update the task with the decrypted username
			taskUserMutex.Lock()
			task.Username = string(decrypted)
			taskUserMutex.Unlock()

		}(&tasks[i], errChan, &wg)

		// decrypted allowance slug
		wg.Add(1)
		go func(task *TaskData, ch chan error, wg *sync.WaitGroup) {
			defer wg.Done()

			// check if the allowance slug is already in the cache
			allowanceMutex.Lock()
			if slug, ok := allowanceCache[task.AllowanceSlug]; ok {
				allowanceMutex.Unlock()

				// update the task with the decrypted allowance slug
				taskAllowanceMutex.Lock()
				task.AllowanceSlug = slug
				taskAllowanceMutex.Unlock()
				return
			}
			allowanceMutex.Unlock()

			// if not, decrypt the allowance slug
			decrypted, err := s.cryptor.DecryptServiceData(task.AllowanceSlug)
			if err != nil {
				errChan <- fmt.Errorf("failed to decrypt allowance slug for task %s: %v", task.Id, err)
				return
			}
			// update the cache of decrypted allowance
			allowanceMutex.Lock()
			allowanceCache[task.AllowanceSlug] = string(decrypted)
			allowanceMutex.Unlock()

			// update the task with the decrypted allowance slug
			taskAllowanceMutex.Lock()
			task.AllowanceSlug = string(decrypted)
			taskAllowanceMutex.Unlock()

		}(&tasks[i], errChan, &wg)
	}

	wg.Wait()
	close(errChan)

	// check for errors in the goroutines
	if len(errChan) > 0 {
		errs := make([]string, len(errChan))
		for e := range errChan {
			errs = append(errs, e.Error())
		}
		return nil, fmt.Errorf("failed to decrypt usernames: %v", strings.Join(errs, "; "))
	}

	return tasks, nil
}

// GetTask is a concrete implementation of the GetTask method in the TaskService interface
// it retrieves a single task record from the database including its template data and allowance username + slug
func (s *taskService) GetTask(slug string) (*TaskData, error) {

	// quick validation of slug
	if len(slug) < 16 || len(slug) > 64 {
		return nil, fmt.Errorf("invalid task slug")
	}

	// get task data from persistence
	record, err := s.db.FindTaskBySlug(slug)
	if err != nil {
		return nil, err
	}

	// decrypt the username and allowance slug
	var (
		wg      sync.WaitGroup
		errChan = make(chan error, 2)

		username      string
		allowanceSlug string
	)

	wg.Add(1)
	go func(encrypted string, decrypted *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		// decrypt the username
		d, err := s.cryptor.DecryptServiceData(encrypted)
		if err != nil {
			errChan <- fmt.Errorf("failed to decrypt username for task (slug %s): %v", slug, err)
			return
		}
		*decrypted = string(d)
	}(record.Username, &username, errChan, &wg)

	wg.Add(1)
	go func(encrypted string, decrypted *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		// decrypt the allowance slug
		d, err := s.cryptor.DecryptServiceData(encrypted)
		if err != nil {
			errChan <- fmt.Errorf("failed to decrypt allowance slug for task (slug %s): %v", slug, err)
			return
		}
		*decrypted = string(d)
	}(record.AllowanceSlug, &allowanceSlug, errChan, &wg)

	wg.Wait()
	close(errChan)
	// check for errors in the goroutines
	if len(errChan) > 0 {
		errs := make([]string, len(errChan))
		for e := range errChan {
			errs = append(errs, e.Error())
		}
		return nil, fmt.Errorf("failed to decrypt db values: %v", strings.Join(errs, "; "))
	}

	// update the task record with the decrypted username and allowance slug
	record.Username = username
	record.AllowanceSlug = allowanceSlug

	// return the task record
	return record, nil
}

// CreateTask is a concrete implementation of the CreateTask method in the TaskService interface
func (s *taskService) CreateTask() (*TaskRecord, error) {

	// generate UUIDs for the task id and slug
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID for task's id: %v", err)
	}

	slug, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID for task's slug: %v", err)
	}

	// create the task record
	task := TaskRecord{
		Id:         id.String(),
		CreatedAt:  data.CustomTime{Time: time.Now().UTC()},
		IsComplete: false,
		CompletedAt: sql.NullTime{
			Valid: false, // indicates NULL
		},
		IsSatisfactory: true, // default to this so you dont have to approve every single one.
		IsProactive:    true, // default to this so you dont have to approve every single one.
		Slug:           slug.String(),
		IsArchived:     false,
	}

	// insert the task record into persistence
	if err := s.db.InsertTask(task); err != nil {
		return nil, fmt.Errorf("failed to insert task record: %w", err)
	}

	return &task, nil
}

// CreateAllowanceXref is a concrete implementation of the CreateAllowanceXref method in the TaskService interface
func (s *taskService) CreateAllowanceXref(t *TaskRecord, a *allowances.Allowance) (*TaskAllowanceXref, error) {

	// create the new xref record
	xref := TaskAllowanceXref{
		Id:          0,
		TaskId:      t.Id,
		AllowanceId: a.Id,
		CreatedAt:   data.CustomTime{Time: time.Now().UTC()},
	}

	// insert the xref record into the database
	if err := s.db.InsertTaskAllowanceXref(xref); err != nil {
		return nil, fmt.Errorf("failed to insert task_allowance xref record: %w", err)
	}

	return &xref, nil
}

// UpdateTask is a concrete implementation of the UpdateTask method in the TaskService interface
func (s *taskService) UpdateTask(t TaskRecord) error {

	return s.db.UpdateTask(t)
}
