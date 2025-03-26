package tasks

import (
	"apprentice/internal/util"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/tasks"
)

// TaskService is an interface to handle task service functionality
type TaskService interface {

	// CreateTask creates a new task record in the database
	CreateTask() (*Task, error)

	// CreateAllowanceXref creates a new allowance-task xref record in the database
	CreateAllowanceXref(t *Task, a *tasks.Allowance) (*TaskAllowanceXref, error)
}

// NewTaskService creates a new TaskService interface, returning a pointer to the concrete implementation
func NewTaskService(sql data.SqlRepository) TaskService {
	return &taskService{
		db: sql,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageTasks)).
			With(slog.String(util.ComponentKey, util.ComponentTasks)),
	}
}

var _ TaskService = (*taskService)(nil)

// taskService is the concrete implementation of the TaskService interface
type taskService struct {
	db data.SqlRepository

	logger *slog.Logger
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
	task := &Task{
		Id:             id.String(),
		CreatedAt:      data.CustomTime{Time: time.Now().UTC()},
		IsComplete:     false,
		IsSatisfactory: true, // i want it to default to this so you dont have to approve every single one.
		IsProactive:    true, // i want it to default to this so you dont have to approve every single one.
		Slug:           slug.String(),
		IsArchived:     false,
	}

	// insert the task record into the database
	qry := `INSERT INTO tasks (uuid, created_at, is_complete, is_satisfactory, is_proactive, slug, is_archived)
			VALUES (?, ?, ?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(qry, task); err != nil {
		errMsg := fmt.Sprintf("failed to insert task record: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	return task, nil
}

// CreateAllowanceXref is a concrete implementation of the CreateAllowanceXref method in the TaskService interface
func (s *taskService) CreateAllowanceXref(t *Task, a *tasks.Allowance) (*TaskAllowanceXref, error) {

	// create the new xref record
	xref := &TaskAllowanceXref{
		TaskId:      t.Id,
		AllowanceId: a.Id,
		CreatedAt:   data.CustomTime{Time: time.Now().UTC()},
	}

	// insert the xref record into the database
	qry := `INSERT INTO task_allowance (task_uuid, allowance_uuid, created_at)
			VALUES (?, ?, ?)`
	if err := s.db.InsertRecord(qry, xref); err != nil {
		errMsg := fmt.Sprintf("failed to insert task-allowance xref record: %v", err)
		s.logger.Error(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	return xref, nil
}
