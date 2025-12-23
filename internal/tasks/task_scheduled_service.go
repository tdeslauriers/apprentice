package tasks

import (
	"database/sql"
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/apprentice/internal/util"
	"github.com/tdeslauriers/apprentice/pkg/api/tasks"
	"github.com/tdeslauriers/carapace/pkg/data"
)

// responsible for scheduled actions on task records
// such as daily, weekly, monthly, etc. task generation,
// marking tasks as archived, etc.
type ScheduledService interface {

	// CreateDailyTasks is a method to created daily tasks
	CreateDailyTasks()

	// CreateWeeklyTasks is a method to create weekly tasks
	CreateWeeklyTasks()
}

// NewScheduledService creates a new ScheduledService interface, returning a pointer to the concrete implementation
func NewScheduledService(sql *sql.DB) ScheduledService {
	return &scheduledService{
		db: NewScheduledRepository(sql),
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
	db ScheduledRepository
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

			loc, err := time.LoadLocation("America/Chicago")
			if err != nil {
				s.logger.Error(fmt.Sprintf("failed to load location: %v", err))
				continue
			}

			now := time.Now().In(loc)

			// set to 1 AM CST to account for +- 30 minutes jitter
			next := time.Date(now.Year(), now.Month(), now.Day(), 1, 0, 0, 0, loc)
			// if 1am has already passed, add a day
			if next.Before(now) {
				next = next.Add(24 * time.Hour)
			}

			// add random jitter +- 30 minutes
			randInterval := time.Duration(rng.Intn(60)-30) * time.Minute
			next = next.Add(randInterval)

			duration := time.Until(next)
			s.logger.Info(fmt.Sprintf("next scheduled daily task creation at %s", next.Format(time.RFC3339)))

			timer := time.NewTimer(duration)
			<-timer.C

			// generate daily tasks: includes check if tasks already created by another instance of the service
			if err := s.generateScheduledTasks(tasks.Daily); err != nil {
				s.logger.Error(fmt.Sprintf("failed to generate daily tasks: %v", err))
				continue
			}

			s.logger.Info("daily task generation complete")
		}
	}()
}

// CreateWeeklyTasks is the concrete implementation of the CreateWeeklyTasks method in the ScheduledService interface
func (s *scheduledService) CreateWeeklyTasks() {

	// will need jitter so that the services do not all run at the same time or disburse on top of each other
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func() {
		for {

			// schedule weekly tasks for Saturday 1 AM CST
			loc, err := time.LoadLocation("America/Chicago")
			if err != nil {
				s.logger.Error(fmt.Sprintf("failed to load location: %v", err))
				continue
			}

			now := time.Now().In(loc)

			// set to 1 AM CST to account for +- 30 minutes jitter
			next := time.Date(now.Year(), now.Month(), now.Day(), 1, 0, 0, 0, loc)

			// calculate days until next Saturday
			daysUntilSaturday := (6 - int(now.Weekday()) + 7) % 7
			if daysUntilSaturday == 0 && now.After(next) {
				daysUntilSaturday = 7
			}

			next = next.AddDate(0, 0, daysUntilSaturday)

			// add jitter to the next time: +- 30 minutes to account for multiple services
			// this is not a security concern, just to avoid all services running at the same time
			randInterval := time.Duration(rng.Intn(60)-30) * time.Minute
			next = next.Add(randInterval)

			s.logger.Info(fmt.Sprintf("next scheduled weekly tasks creation at %s", next.Format(time.RFC3339)))

			duration := time.Until(next)
			timer := time.NewTimer(duration)
			<-timer.C

			// generate weekly tasks: includes check if tasks already created by another instance of the service
			if err := s.generateScheduledTasks(tasks.Weekly); err != nil {
				s.logger.Error(fmt.Sprintf("failed to generate weekly tasks: %v", err))
				continue
			}

			s.logger.Info("weekly task generation complete")
		}
	}()
}

// generateScheduledTasks is a helper method to generate scheduled tasks.
// It takes a cadence and inserts it into sql statements and preforms the task generation.
func (s *scheduledService) generateScheduledTasks(cadence tasks.Cadence) error {

	// check if tasks already created by another instance of the service
	exists, err := s.db.TaskExistsByCadence(cadence)
	if exists {
		s.logger.Info(fmt.Sprintf("%s tasks already created, skipping task generation",
			strings.ToLower(string(cadence))))
		return nil
	}
	if err != nil {
		return fmt.Errorf("error selecting for existing %s tasks: %v",
			strings.ToLower(string(cadence)), err)
	}

	// get the tasks for creation based on cadence
	toGenerate, err := s.db.FindTemplates(cadence)
	if err != nil {
		return fmt.Errorf("failed to query %s tasks for creation: %v", strings.ToLower(string(cadence)), err)
	}

	if len(toGenerate) <= 0 {
		s.logger.Info(fmt.Sprintf("no %s tasks to generate at this time", strings.ToLower(string(cadence))))
		return nil
	}

	// caputre unique template uuids
	// key is the template uuid so unique, and then the value is a slice of allowance uuids
	// for templates that need a new task for each allowance/assignee
	gen := make(map[string][]string, len(toGenerate))
	for _, w := range toGenerate {
		if _, ok := gen[w.TemplateId]; !ok {
			gen[w.TemplateId] = make([]string, 0)
		}
		gen[w.TemplateId] = append(gen[w.TemplateId], w.AllowanceId)
	}

	// create the tasks
	for templateId, allowances := range gen {
		for _, allowanceId := range allowances {
			// create the task
			// generate a new uuid for the task
			id, err := uuid.NewRandom()
			if err != nil {
				return fmt.Errorf("failed to create uuid for %s task generation: %v", strings.ToLower(string(cadence)), err)

			}

			// generate task slug
			slug, err := uuid.NewRandom()
			if err != nil {
				return fmt.Errorf("failed to create slug for %s task generation: %v", strings.ToLower(string(cadence)), err)
			}

			task := TaskRecord{
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
			if err := s.db.InsertTaskRecord(task); err != nil {
				return fmt.Errorf("failed to create %s task in database: %v", strings.ToLower(string(cadence)), err)
			}

			// create the template-task xref
			ttXref := TemplateTaskXref{
				Id:         0, // auto increment
				TemplateId: templateId,
				TaskId:     task.Id,
				CreatedAt:  data.CustomTime{Time: time.Now().UTC()},
			}

			if err := s.db.InsertTemplateTaskXref(ttXref); err != nil {
				s.logger.Error(fmt.Sprintf("failed to create template-task xref in database for %s task generation: %v",
					strings.ToLower(string(cadence)), err))
			}

			// create the task-allowance xref
			taXref := TaskAllowanceXref{
				Id:          0, // auto increment
				TaskId:      task.Id,
				AllowanceId: allowanceId,
				CreatedAt: data.CustomTime{
					Time: time.Now().UTC(),
				},
			}

			if err := s.db.InsertTaskAllowanceXref(taXref); err != nil {
				s.logger.Error(fmt.Sprintf("failed to create task-allowance xref in database for %s task generation: %v",
					strings.ToLower(string(cadence)), err))
			}

			s.logger.Info(fmt.Sprintf("created %s task %s for template %s and allowance %s",
				strings.ToLower(string(cadence)), task.Id, templateId, allowanceId))
		}
	}
	return nil
}
