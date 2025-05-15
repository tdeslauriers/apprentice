package tasks

import (
	"apprentice/internal/util"
	"database/sql"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/permissions"
	"github.com/tdeslauriers/carapace/pkg/tasks"
)

// TaskService is an interface to handle task service functionality
type TaskService interface {

	// GetTasks retrieves all task records from the database that an allowance user has
	// permission to access based on query parameters if they exist
	// Note: this is meant to be a Get All Tasks function and will default to returning all tasks (based on permissions)
	// username (should come from a valid source like jwt subject) needed if permissions do not
	// allow getting all tasks: it will filter for just that user's tasks
	GetTasks(username string, paramas url.Values, permissions map[string]permissions.Permission) ([]TaskRecord, error)

	// GetTask retrieves a single task record from the database including its template data and allowance username + slug
	GetTask(slug string) (*TaskRecord, error)

	// CreateTask creates a new task record in the database
	CreateTask() (*Task, error)

	// CreateAllowanceXref creates a new allowance-task xref record in the database
	CreateAllowanceXref(t *Task, a *tasks.Allowance) (*TaskAllowanceXref, error)

	// UpdateTask updates a task record in the database
	UpdateTask(t Task) error
}

// NewTaskService creates a new TaskService interface, returning a pointer to the concrete implementation
func NewTaskService(sql data.SqlRepository, i data.Indexer, c data.Cryptor) TaskService {
	return &taskService{
		db:      sql,
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
	db      data.SqlRepository
	indexer data.Indexer
	cryptor data.Cryptor

	logger *slog.Logger
}

// GetTasks is a concrete implementation of the GetTasks method in the TaskService interface
// internally, it uses a query builder to build the query based on the parameters and permissions passed in
func (s *taskService) GetTasks(username string, params url.Values, permissions map[string]permissions.Permission) ([]TaskRecord, error) {

	// build the query string and arguments
	qry, args, err := s.buildTaskQuery(username, params, permissions)
	if err != nil {
		return nil, fmt.Errorf("failed to build task query: %v", err)
	}

	// execute the query and get the results
	var tasks []TaskRecord
	if err := s.db.SelectRecords(qry, &tasks, args...); err != nil {
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
		go func(task *TaskRecord, ch chan error, wg *sync.WaitGroup) {
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
		go func(task *TaskRecord, ch chan error, wg *sync.WaitGroup) {
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
func (s *taskService) GetTask(slug string) (*TaskRecord, error) {

	// quick validation of slug
	if len(slug) < 16 || len(slug) > 64 {
		return nil, fmt.Errorf("invalid task slug")
	}

	// build the query string
	qry := `SELECT
				tsk.uuid,
				tmp.name,
				tmp.description,
				tmp.cadence,
				tmp.category,
				tsk.created_at,
				tsk.is_complete,
				COALESCE(tsk.completed_at, '') AS completed_at,
				tsk.is_satisfactory,
				tsk.is_proactive,
				tsk.slug AS task_slug,
				tsk.is_archived,
				a.username,
				a.slug AS allowance_slug
			FROM task tsk
				LEFT OUTER JOIN template_task tt ON tsk.uuid = tt.task_uuid
				LEFT OUTER JOIN template tmp ON tt.template_uuid = tmp.uuid
				LEFT OUTER JOIN task_allowance ta ON tsk.uuid = ta.task_uuid
				LEFT OUTER JOIN allowance a ON ta.allowance_uuid = a.uuid
			WHERE tsk.slug = ?`
	var record TaskRecord
	if err := s.db.SelectRecord(qry, &record, slug); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no task record found for slug %s", slug)
		}
		return nil, fmt.Errorf("failed to retrieve task (slug %s) record: %v", slug, err)
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
	return &record, nil
}

// CreateTask is a concrete implementation of the CreateTask method in the TaskService interface
func (s *taskService) CreateTask() (*Task, error) {

	// generate UUIDs for the task id and slug
	id, err := uuid.NewRandom()
	if err != nil {
		errMsg := fmt.Sprintf("failed to generate UUID for task id: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	slug, err := uuid.NewRandom()
	if err != nil {
		errMsg := fmt.Sprintf("failed to generate UUID for task slug: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	// create the task record
	task := Task{
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

	// insert the task record into the database
	qry := `INSERT INTO task (uuid, created_at, is_complete, completed_at, is_satisfactory, is_proactive, slug, is_archived)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, task); err != nil {
		errMsg := fmt.Sprintf("failed to insert task record: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	s.logger.Info(fmt.Sprintf("successfully created task record with slug %s", task.Slug))

	return &task, nil
}

// CreateAllowanceXref is a concrete implementation of the CreateAllowanceXref method in the TaskService interface
func (s *taskService) CreateAllowanceXref(t *Task, a *tasks.Allowance) (*TaskAllowanceXref, error) {

	// create the new xref record
	xref := TaskAllowanceXref{
		Id:          0,
		TaskId:      t.Id,
		AllowanceId: a.Id,
		CreatedAt:   data.CustomTime{Time: time.Now().UTC()},
	}

	// insert the xref record into the database
	qry := `INSERT INTO task_allowance (id, task_uuid, allowance_uuid, created_at)
			VALUES (?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, xref); err != nil {
		errMsg := fmt.Sprintf("failed to insert task_allowance xref record: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	s.logger.Info(fmt.Sprintf("successfully created xref record between task %s and allowance %s", t.Slug, a.Username))

	return &xref, nil
}

// UpdateTask is a concrete implementation of the UpdateTask method in the TaskService interface
func (s *taskService) UpdateTask(t Task) error {

	// update the task record in the database
	// these are the only field that may be updated. The rest are immutable
	qry := `UPDATE task
			SET is_complete = ?, completed_at = ?, is_satisfactory = ?, is_proactive = ?, is_archived = ?
			WHERE uuid = ?`
	if err := s.db.UpdateRecord(qry, t.IsComplete, t.CompletedAt, t.IsSatisfactory, t.IsProactive, t.IsArchived, t.Id); err != nil {
		errMsg := fmt.Sprintf("failed to update task record: %v", err)
		return fmt.Errorf(errMsg)
	}

	return nil
}

// buildTaskQuery is a function that builds a SQL query string based on the provided parameters and permissions
// It returns the query string and any error encountered during the process
// username is needed if permissions dont allow getting all tasks: it will filter for just that user's tasks
func (s *taskService) buildTaskQuery(username string, params url.Values, permissions map[string]permissions.Permission) (string, []interface{}, error) {

	// validate params: redundant, but good practice.
	if err := tasks.ValidateQueryParams(params); err != nil {
		return "", nil, err
	}

	var qry strings.Builder

	// default query
	// note: even the default query is a join, because need to get the template data
	qry.WriteString(`SELECT
				tsk.uuid,
				tmp.name,
				tmp.description,
				tmp.cadence,
				tmp.category,
				tsk.created_at,
				tsk.is_complete,
				COALESCE(tsk.completed_at, '') AS completed_at,
				tsk.is_satisfactory,
				tsk.is_proactive,
				tsk.slug AS task_slug,
				tsk.is_archived,
				a.username,
				a.slug AS allowance_slug
			FROM task tsk
				LEFT OUTER JOIN template_task tt ON tsk.uuid = tt.task_uuid
				LEFT OUTER JOIN template tmp ON tt.template_uuid = tmp.uuid
				LEFT OUTER JOIN task_allowance ta ON tsk.uuid = ta.task_uuid
				LEFT OUTER JOIN allowance a ON ta.allowance_uuid = a.uuid`)

	// slices to hold the query parameters/where clauses and their corresponding values/arguments
	whereClauses := []string{}
	args := []interface{}{}

	// need to handle premissions to determine if the user has permission access all task records for all users
	// or just their own tasks and add this filter to the query immediately before anything else
	if _, ok := permissions["payroll"]; !ok {

		s.logger.Info(fmt.Sprintf("user %s does not have permission to get all tasks, building query for only their tasks", username))

		// get user index from username (from jwt)
		index, err := s.indexer.ObtainBlindIndex(username)
		if err != nil {
			errMsg := fmt.Sprintf("failed to get user index for %s: %v", username, err)
			s.logger.Error(errMsg)
			return "", nil, fmt.Errorf(errMsg)
		}

		whereClauses = append(whereClauses, "a.user_index = ?")
		args = append(args, index)
	}

	// handle pre-cooked dashboard/db views queries
	// 'today' does not mean "only open/created today", but also includes any open weekly, monthly, etc. tasks
	// IE, it means 'for today'
	if params.Has("view") && params.Get("view") != "" {
		if params.Get("view") == "today" {

			now := time.Now().UTC()

			// get the start of today in UTC
			todayStart := time.Date(
				now.Year(), now.Month(), now.Day(),
				0, 0, 0, 0, time.UTC,
			).Add(+5 * time.Hour) // adjust for UTC-6 (+5 cuz daylight savings)

			// get tomorrow start in UTC
			tomorrowStart := time.Date(
				now.Year(), now.Month(), now.Day(),
				0, 0, 0, 0, time.UTC,
			).Add(24 * time.Hour).Add(+5 * time.Hour) // adjust for UTC-6 (+5 cuz daylight savings)

			// add the where clause for tasks created today OR not complete and not daily OR completed today
			// Note: many daily tasks will end up incomplete, so is_completed = false AND cadence <> 'DAILY'
			whereClauses = append(whereClauses,
				`((tsk.created_at >= ? AND tsk.created_at <= ? AND tmp.cadence = 'DAILY') 
				OR (tsk.is_complete = FALSE AND tmp.cadence <> 'DAILY') 
				OR (tsk.completed_at >= ? AND tsk.completed_at <= ?))`)
			args = append(args, todayStart.Format("2006-01-02 15:04:05"))
			args = append(args, tomorrowStart.Format("2006-01-02 15:04:05"))
			args = append(args, todayStart.Format("2006-01-02 15:04:05"))
			args = append(args, tomorrowStart.Format("2006-01-02 15:04:05"))
		}
	}

	// handle assignee codes and filtering
	// if assignee = "me" and user does NOT have the payroll permsision, then do nothing because filter already applied above
	if params.Has("assignee") {

		if _, ok := permissions["payroll"]; ok {

			// split parameter values by comma if necessary and consolidate to single slice/array
			var assigneeList []string
			for _, v := range params["assignee"] {
				// seperate vaues by comma
				as := strings.Split(v, ",")
				for _, a := range as {
					assigneeList = append(assigneeList, strings.TrimSpace(strings.ToLower(a)))
				}
			}

			// all is default behavior, so only need to handle adding sql syntax if me or/and other user slugs are present
			// including 'all' in a list greater than 1 will cause a validation error, so no need to check for that

			assigneeClauses := []string{}
			for _, a := range assigneeList {

				if a == "me" {
					// get user index from username (from jwt)
					index, err := s.indexer.ObtainBlindIndex(username)
					if err != nil {
						return "", nil, fmt.Errorf("failed to get user index for %s: %v", username, err)
					}
					// add the where clause for the user index
					assigneeClauses = append(assigneeClauses, "a.user_index = ?")
					args = append(args, index)

				}

				if a != "me" && a != "all" {
					// get the allowance index from the slug
					index, err := s.indexer.ObtainBlindIndex(a)
					if err != nil {
						return "", nil, fmt.Errorf("failed to get allowance slug index for %s: %v", a, err)
					}
					// add the where clause for the allowance slug
					assigneeClauses = append(assigneeClauses, "a.slug_index = ?")
					args = append(args, index)
				}
			}
			// join the user filtering clauses with OR and add to the where clauses
			if len(assigneeClauses) > 0 {
				assigneeSql := strings.Join(assigneeClauses, " OR ")
				whereClauses = append(whereClauses, fmt.Sprintf("(%s)", assigneeSql))
			}
		}
	}

	// handle name params and where clauses
	if params.Has("name") {

		// split parameter values by comma if necessary and consolidate to single slice/array
		var nameList []string
		for _, v := range params["name"] {
			// seperate vaues by comma
			n := strings.Split(v, ",")
			for _, a := range n {
				nameList = append(nameList, strings.TrimSpace(strings.ToLower(a)))
			}
		}

		// build name sql clauses and add name strings to args
		var nameClauses []string
		for _, n := range nameList {
			nameClauses = append(nameClauses, "tmp.name LIKE ?")
			args = append(args, "%"+n+"%")
		}
		nameSql := strings.Join(nameClauses, " OR ")
		whereClauses = append(whereClauses, fmt.Sprintf("(%s)", nameSql))
	}

	// handle cadence params and where clauses
	if params.Has("cadence") {
		// split parameter values by comma if necessary and consolidate to single slice/array
		var cadenceList []string
		for _, v := range params["cadence"] {
			// seperate vaues by comma
			c := strings.Split(v, ",")
			for _, a := range c {
				cadenceList = append(cadenceList, strings.TrimSpace(strings.ToUpper(a)))
			}
		}

		// build cadence sql clauses and add cadence strings to args
		var cadenceClauses []string
		for _, c := range cadenceList {
			cadenceClauses = append(cadenceClauses, "tmp.cadence = ?")
			args = append(args, c)
		}
		cadenceSql := strings.Join(cadenceClauses, " OR ")
		whereClauses = append(whereClauses, fmt.Sprintf("(%s)", cadenceSql))
	}

	// handle category params and where clauses
	if params.Has("category") {
		// split parameter values by comma if necessary and consolidate to single slice/array
		var categoryList []string
		for _, v := range params["category"] {
			// seperate vaues by comma
			c := strings.Split(v, ",")
			for _, a := range c {
				categoryList = append(categoryList, strings.TrimSpace(strings.ToUpper(a)))
			}
		}

		// build category sql clauses and add category strings to args
		var categoryClauses []string
		for _, c := range categoryList {
			categoryClauses = append(categoryClauses, "tmp.category = ?")
			args = append(args, c)
		}
		categorySql := strings.Join(categoryClauses, " OR ")
		whereClauses = append(whereClauses, fmt.Sprintf("(%s)", categorySql))
	}

	// handle is_complete params and where clause
	if params.Has("is_complete") {
		// split parameter values by comma if necessary and consolidate to single slice/array
		var isCompleteList []string
		for _, v := range params["is_complete"] {
			// seperate vaues by comma
			c := strings.Split(v, ",")
			for _, a := range c {
				isCompleteList = append(isCompleteList, strings.TrimSpace(strings.ToUpper(a)))
			}
		}

		// there should only be 1 value in the list
		// param validation should have already been done, but just in case
		if len(isCompleteList) > 1 {
			return "", nil, fmt.Errorf("is_complete parameter can only be true or false")
		}

		// build is_complete sql clause and add is_complete string to args
		// note: being explicit about true/false to avoid sql errors
		// this is a bit redundant, but it makes the code easier to read
		var isCompleteClause string
		if strings.ToUpper(isCompleteList[0]) == "TRUE" {
			isCompleteClause = "tsk.is_complete = TRUE"
		}
		if strings.ToUpper(isCompleteList[0]) == "FALSE" {
			isCompleteClause = "tsk.is_complete = FALSE"
		}

		whereClauses = append(whereClauses, isCompleteClause)
	}

	// handle is_satisfactory params and where clause
	if params.Has("is_satisfactory") {
		// split parameter values by comma if necessary and consolidate to single slice/array
		var isSatisfactoryList []string
		for _, v := range params["is_satisfactory"] {
			// seperate vaues by comma
			c := strings.Split(v, ",")
			for _, a := range c {
				isSatisfactoryList = append(isSatisfactoryList, strings.TrimSpace(strings.ToUpper(a)))
			}
		}

		// there should only be 1 value in the list
		// param validation should have already been done, but just in case
		if len(isSatisfactoryList) > 1 {
			return "", nil, fmt.Errorf("is_satisfactory parameter can only be true or false")
		}

		// build is_satisfactory sql clause and add is_satisfactory string to args
		var isSatisfactoryClause string
		if strings.ToUpper(isSatisfactoryList[0]) == "TRUE" {
			isSatisfactoryClause = "tsk.is_satisfactory = TRUE"
		}
		if strings.ToUpper(isSatisfactoryList[0]) == "FALSE" {
			isSatisfactoryClause = "tsk.is_satisfactory = FALSE"
		}

		whereClauses = append(whereClauses, isSatisfactoryClause)
	}

	// handle is_proactive params and where clause
	if params.Has("is_proactive") {
		// split parameter values by comma if necessary and consolidate to single slice/array
		var isProactiveList []string
		for _, v := range params["is_proactive"] {
			// seperate vaues by comma
			c := strings.Split(v, ",")
			for _, a := range c {
				isProactiveList = append(isProactiveList, strings.TrimSpace(strings.ToUpper(a)))
			}
		}

		// there should only be 1 value in the list
		// param validation should have already been done, but just in case
		if len(isProactiveList) > 1 {
			return "", nil, fmt.Errorf("is_proactive parameter can only be true or false")
		}

		// build is_proactive sql clause and add is_proactive string to args
		var isProactiveClause string
		if strings.ToUpper(isProactiveList[0]) == "TRUE" {
			isProactiveClause = "tsk.is_proactive = TRUE"
		}
		if strings.ToUpper(isProactiveList[0]) == "FALSE" {
			isProactiveClause = "tsk.is_proactive = FALSE"
		}

		whereClauses = append(whereClauses, isProactiveClause)
	}

	// handle is_archived params and where clause
	if params.Has("is_archived") {
		// split parameter values by comma if necessary and consolidate to single slice/array
		var isArchivedList []string
		for _, v := range params["is_archived"] {
			// seperate vaues by comma
			c := strings.Split(v, ",")
			for _, a := range c {
				isArchivedList = append(isArchivedList, strings.TrimSpace(strings.ToUpper(a)))
			}
		}

		// there should only be 1 value in the list
		// param validation should have already been done, but just in case
		if len(isArchivedList) > 1 {
			return "", nil, fmt.Errorf("is_archived parameter can only be true or false")
		}

		// build is_archived sql clause and add is_archived string to args
		var isArchivedClause string
		if strings.ToUpper(isArchivedList[0]) == "TRUE" {
			isArchivedClause = "tsk.is_archived = TRUE"
		}
		if strings.ToUpper(isArchivedList[0]) == "FALSE" {
			isArchivedClause = "tsk.is_archived = FALSE"
		}

		whereClauses = append(whereClauses, isArchivedClause)
	}

	// build the final query string
	if len(whereClauses) > 0 {
		qry.WriteString(" WHERE ")
		qry.WriteString(strings.Join(whereClauses, " AND "))
	}

	return qry.String(), args, nil
}
