package tasks

import (
	"apprentice/internal/util"
	"database/sql"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
)

// responsible for scheduled actions on task records
// such as daily, weekly, monthly, etc. task generation,
// marking tasks as archived, etc.
type ScheduledService interface {

	// Daily is a method to created daily tasks
	CreateDailyTasks()
}

// NewScheduledService creates a new ScheduledService interface, returning a pointer to the concrete implementation
func NewScheduledService(sql data.SqlRepository) ScheduledService {
	return &scheduledService{
		db: sql,
		// indexer: i, // indexer not needed thus far
		// cryptor: c, // cryptor not needed thus far

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageTasks)).
			With(slog.String(util.ComponentKey, util.ComponentScheduledTasks)),
	}
}

var _ ScheduledService = (*scheduledService)(nil)

// scheduledService is the concrete implementation of the ScheduledService interface
type scheduledService struct {
	db data.SqlRepository
	// indexer data.Indexer // indexer not needed thus far
	// cryptor data.Cryptor // cryptor not needed thus far
	logger *slog.Logger
}

// CreateDailyTasks is the concrete implementation of the CreateDailyTasks method in the ScheduledService interface
func (s *scheduledService) CreateDailyTasks() {

	// there is more than one service instance, so each needs to check if others have already created tasks
	// they also cant create tasks at the same time, so we need to build in some jitter
	// create local random generator -> doesnt need to be cryptographically secure
	// this is not a security concern -> just so they dont go at the same time.
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func() {
		for {

			now := time.Now().UTC()

			// calc next 3am (local time) -> which is 9AM UTC
			next := time.Date(now.Year(), now.Month(), now.Day(), 9, 0, 0, 0, time.UTC)
			// if 3am has already passed, add a day
			if next.Before(now) {
				next = next.Add(24 * time.Hour)
			}

			// add random jitter +- 30 minutes
			randInterval := time.Duration(rng.Intn(60)-30) * time.Minute
			next = next.Add(randInterval)

			duration := time.Until(next)
			s.logger.Info(fmt.Sprintf("next scheduled task creation at %s", next.Format(time.RFC3339)))

			timer := time.NewTimer(duration)
			<-timer.C

			// check if tasks already created by another instance of the service
			// just need to check for one record because if one Daily task exists for the day, they all do
			qry := `SELECT EXISTS
						(SELECT 1 
						FROM task t
							LEFT OUTER JOIN template_task tt ON t.uuid = tt.task_uuid
							LEFT OUTER JOIN template tem ON tt.template_uuid = tem.uuid
						WHERE tem.cadence = 'DAILY'
							AND t.created_at >= UTC_TIMESTAMP() - INTERVAL 2 HOUR)`
			ok, err := s.db.SelectExists(qry)
			if ok {
				s.logger.Info("daily tasks already created for today, skipping task generation")
			}
			if err != nil {
				s.logger.Error(fmt.Sprintf("error checking for existing daily tasks: %v", err))
				return
			}

			// get the daily tasks for creation
			qry = `SELECT 
					t.uuid AS template_uuid,
					ta.allowance_uuid AS allowance_uuid
				FROM template t
					LEFT OUTER JOIN template_allowance ta ON t.uuid = ta.template_uuid
				WHERE t.cadence = 'DAILY'
					AND t.is_archived = false`
			var daily []DailyGen
			if err := s.db.SelectRecords(qry, &daily); err != nil {
				if err == sql.ErrNoRows {
					s.logger.Warn("no daily tasks/templates found for creation in db")
					return
				} else {
					s.logger.Error(fmt.Sprintf("failed to query daily tasks for creation: %v", err))
					return
				}
			}

			// caputre unique template uuids
			// key is the template uuid so unique, and then the value is a slice of allowance uuids
			// for templates that need a new task for each allowance/assignee
			gen := make(map[string][]string, len(daily))
			for _, d := range daily {
				if _, ok := gen[d.TemplateId]; !ok {
					gen[d.TemplateId] = make([]string, 0)
				}
				gen[d.TemplateId] = append(gen[d.TemplateId], d.AllowanceId)
			}

			// create the tasks
			for templateId, allowances := range gen {
				for _, allowanceId := range allowances {
					// create the task
					// generate a new uuid for the task
					id, err := uuid.NewRandom()
					if err != nil {
						s.logger.Error(fmt.Sprintf("failed to create uuid for daily task generation: %v", err))
						return
					}

					// generate task slug
					slug, err := uuid.NewRandom()
					if err != nil {
						s.logger.Error(fmt.Sprintf("failed to create slug for daily task generation: %v", err))
					}

					task := Task{
						Id:             id.String(),
						CreatedAt:      data.CustomTime{Time: time.Now().UTC()},
						IsComplete:     false,
						CompletedAt:    sql.NullTime{},
						IsSatisfactory: true,
						IsProactive:    true,
						Slug:           slug.String(),
						IsArchived:     false,
					}

					// create the task
					qry = `INSERT INTO task (uuid, created_at, is_complete, completed_at, is_satisfactory, is_proactive, slug, is_archived) 
							VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
					if err := s.db.InsertRecord(qry, task); err != nil {
						s.logger.Error(fmt.Sprintf("failed to create daily task in database: %v", err))
						return
					}

					// create the template-task xref
					ttXref := TemplateTaskXref{
						Id:         0, // auto increment
						TemplateId: templateId,
						TaskId:     task.Id,
						CreatedAt:  data.CustomTime{Time: time.Now().UTC()},
					}

					qry = `INSERT INTO template_task (id, template_uuid, task_uuid, created_at)
							VALUES (?, ?, ?, ?)`
					if err := s.db.InsertRecord(qry, ttXref); err != nil {
						s.logger.Error(fmt.Sprintf("failed to create template-task xref in database for daily task generation: %v", err))
						return
					}

					// create the task-allowance xref
					taXref := TaskAllowanceXref{
						Id:          0, // auto increment
						TaskId:      task.Id,
						AllowanceId: allowanceId,
						CreatedAt:   data.CustomTime{Time: time.Now().UTC()},
					}

					qry = `INSERT INTO task_allowance (id, task_uuid, allowance_uuid, created_at)
							VALUES (?, ?, ?, ?)`
					if err := s.db.InsertRecord(qry, taXref); err != nil {
						s.logger.Error(fmt.Sprintf("failed to create task-allowance xref in database for daily task generation: %v", err))
						return
					}

					s.logger.Info(fmt.Sprintf("created daily task %s for template %s and allowance %s", task.Id, templateId, allowanceId))
				}
			}
			s.logger.Info("daily task generation complete")
		}
	}()
}
