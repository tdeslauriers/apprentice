package tasks

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/tdeslauriers/apprentice/internal/util"
	"github.com/tdeslauriers/apprentice/pkg/api/tasks"
	"github.com/tdeslauriers/carapace/pkg/data"
	exo "github.com/tdeslauriers/carapace/pkg/permissions"
)

// TaskRepository defines the interface for tasks data operations.
type TaskRepository interface {

	// FindTasksByParams retrieves tasks from the database based on the provided parameters and user permissions.
	FindTasksByParams(
		username string,
		params url.Values,
		permissions map[string]exo.PermissionRecord,
	) ([]tasks.TaskData, error)

	// FindTaskBySlug retrieves a Task record and its associated Template data by the task's slug.
	FindTaskBySlug(slug string) (*tasks.TaskData, error)

	// InsertTask adds a new task record to the database.
	InsertTask(record TaskRecord) error

	// InsertTaskAllowanceXref adds a new xref record to the task_allowance table in the database.
	InsertTaskAllowanceXref(xref TaskAllowanceXref) error

	// UpdateTask updates specific fields of the task model in the database.
	UpdateTask(t TaskRecord) error
}

// NewTaskRepository creates a new instance of TaskAdapter.
func NewTaskRepository(sql *sql.DB, i data.Indexer) TaskRepository {
	return &taskAdapter{
		db:      sql,
		indexer: i,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageTasks)).
			With(slog.String(util.ComponentKey, util.ComponentTasks)),
	}
}

var _ TaskRepository = (*taskAdapter)(nil)

// taskAdapter is a concrete implementation of TaskRepository.
type taskAdapter struct {
	db      *sql.DB
	indexer data.Indexer

	logger *slog.Logger
}

// FindTasksByParams retrieves tasks from the database based on the provided parameters and user permissions.
func (s *taskAdapter) FindTasksByParams(
	username string,
	params url.Values,
	permissions map[string]exo.PermissionRecord,
) ([]tasks.TaskData, error) {

	// build the query based on params and permissions
	query, args, err := s.buildTaskQuery(username, params, permissions)
	if err != nil {
		return nil, fmt.Errorf("failed to build task query: %v", err)
	}

	return data.SelectRecords[tasks.TaskData](s.db, query, args...)
}

// FindTaskBySlug retrieves a Task record and its associated Template data by the task's slug.
func (s *taskAdapter) FindTaskBySlug(slug string) (*tasks.TaskData, error) {

	qry := `
		SELECT
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
			COALESCE(a.username, '') AS username,
			COALESCE(a.slug, '') AS allowance_slug
		FROM task tsk
			LEFT OUTER JOIN template_task tt ON tsk.uuid = tt.task_uuid
			LEFT OUTER JOIN template tmp ON tt.template_uuid = tmp.uuid
			LEFT OUTER JOIN task_allowance ta ON tsk.uuid = ta.task_uuid
			LEFT OUTER JOIN allowance a ON ta.allowance_uuid = a.uuid
		WHERE tsk.slug = ?`

	td, err := data.SelectOneRecord[tasks.TaskData](s.db, qry, slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("task record not found for slug %s", slug)
		}
		return nil, fmt.Errorf("failed to retrieve task (slug %s) record: %v", slug, err)
	}

	return &td, nil
}

// InsertTask adds a new task record to the database.
func (s *taskAdapter) InsertTask(record TaskRecord) error {

	qry := `
		INSERT INTO task (
			uuid, 
			created_at, 
			is_complete, 
			completed_at, 
			is_satisfactory, 
			is_proactive, 
			slug, 
			is_archived
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	return data.InsertRecord(s.db, qry, record)
}

// InsertTaskAllowanceXref adds a new xref record to the task_allowance table in the database.
func (s *taskAdapter) InsertTaskAllowanceXref(xref TaskAllowanceXref) error {

	qry := `
		INSERT INTO task_allowance (
			id, 
			task_uuid, 
			allowance_uuid, 
			created_at
		) VALUES (?, ?, ?, ?)`

	return data.InsertRecord(s.db, qry, xref)
}

// UpdateTask updates specific fields of the task model in the database.  Specifically,
// is_complete, completed_at, is_satisfactory, is_proactive, is_archived.
func (s *taskAdapter) UpdateTask(t TaskRecord) error {

	qry := `
		UPDATE task SET 
			is_complete = ?, 
			completed_at = ?, 
			is_satisfactory = ?, 
			is_proactive = ?, 
			is_archived = ?
		WHERE uuid = ?`

	return data.UpdateRecord(
		s.db,
		qry,
		t.IsComplete,     // to update
		t.CompletedAt,    // to update
		t.IsSatisfactory, // to update
		t.IsProactive,    // to update
		t.IsArchived,     // to update
		t.Id,             // for lookup/WHERE clause
	)
}

// buildTaskQuery is a function that builds a SQL query string based on the provided parameters and permissions
// It returns the query string and any error encountered during the process
// username is needed if permissions dont allow getting all tasks: it will filter for just that user's tasks
func (s *taskAdapter) buildTaskQuery(
	username string,
	params url.Values,
	permissions map[string]exo.PermissionRecord,
) (string, []interface{}, error) {

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
	if _, ok := permissions[util.PermissionPayroll]; !ok {

		s.logger.Info(fmt.Sprintf("user %s does not have permission to get all tasks, building query for only their tasks", username))

		// get user index from username (from jwt)
		index, err := s.indexer.ObtainBlindIndex(username)
		if err != nil {
			return "", nil, fmt.Errorf("failed to get user index for %s: %v", username, err)
		}

		whereClauses = append(whereClauses, "a.user_index = ?")
		args = append(args, index)
	}

	// handle pre-cooked dashboard/db views queries
	// 'today' does not mean "only open/created today", but also includes any open weekly, monthly, etc. tasks
	// IE, it means 'for today'
	if params.Has("view") && params.Get("view") != "" {
		if params.Get("view") == "today" {

			loc, err := time.LoadLocation("America/Chicago")
			if err != nil {
				return "", nil, fmt.Errorf("failed to load local location timezone: %v", err)
			}

			now := time.Now().In(loc)

			// interval from 12:01 AM to 11:59 PM Central time
			startOfDayLocal := time.Date(
				now.Year(), now.Month(), now.Day(),
				0, 1, 0, 0, loc, // 12:01 AM
			)
			endOfDayLocal := time.Date(
				now.Year(), now.Month(), now.Day(),
				23, 59, 0, 0, loc, // 11:59 PM
			)

			// convert to UTC for db lookup since all times in UTC in db
			startUTC := startOfDayLocal.UTC()
			endUTC := endOfDayLocal.UTC()

			// add the where clause for tasks created today OR not complete and not daily OR completed today
			// Note: many daily tasks will end up incomplete, so is_completed = false AND cadence <> 'DAILY'
			whereClauses = append(whereClauses,
				`((tsk.created_at >= ? AND tsk.created_at <= ? AND tmp.cadence = 'DAILY') 
				OR (tsk.is_complete = FALSE AND tmp.cadence <> 'DAILY') 
				OR (tsk.completed_at >= ? AND tsk.completed_at <= ?))`)
			args = append(args, startUTC.Format("2006-01-02 15:04:05"))
			args = append(args, endUTC.Format("2006-01-02 15:04:05"))
			args = append(args, startUTC.Format("2006-01-02 15:04:05"))
			args = append(args, endUTC.Format("2006-01-02 15:04:05"))
		}
	}

	// handle assignee codes and filtering
	// if assignee = "me" and user does NOT have the payroll permsision, then do nothing because filter already applied above
	if params.Has("assignee") {

		if _, ok := permissions[util.PermissionPayroll]; ok {

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
