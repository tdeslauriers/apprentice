package remittance

import (
	"apprentice/internal/util"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand"
	"net/url"
	"time"

	"github.com/tdeslauriers/carapace/pkg/connect"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/profile"
	"github.com/tdeslauriers/carapace/pkg/session/provider"
)

// RemittanceService is an interface for the methods and functionality surrounding remittance of allowances,
// ie, calculating and applying payments to allowance accounts.
type Service interface {
	// Disburse is a method to disburse allowances to the appropriate accounts
	// based on the tasks/chores assigned and completed, accounting for satisfactory and proactive completion.
	Disburse()
}

// NewRemittanceService creates a new RemittanceService interface, returning a pointer to the concrete implementation
func NewService(sql data.SqlRepository, i data.Indexer, c data.Cryptor, tkn provider.S2sTokenProvider, identity connect.S2sCaller) Service {
	return &service{
		sql:      sql,
		indexer:  i,
		cryptor:  c,
		tkn:      tkn,
		identity: identity,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageAllowances)).
			With(slog.String(util.ComponentKey, util.ComponentRemittance)),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the RemittanceService interface
type service struct {
	sql      data.SqlRepository
	indexer  data.Indexer
	cryptor  data.Cryptor
	tkn      provider.S2sTokenProvider
	identity connect.S2sCaller

	logger *slog.Logger
}

// Disburse is a concrete implementation of the Disburse method in the RemittanceService interface
func (s *service) Disburse() {

	// will need jitter so that the services do not all run at the same time or disburse on top of each other
	src := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(src)

	go func() {
		for {

			// schedule weekly tasks for Saturday 12.01 AM CST
			loc, err := time.LoadLocation("America/Chicago")
			if err != nil {
				s.logger.Error(fmt.Sprintf("failed to load location: %v", err))
				continue
			}

			now := time.Now().In(loc)

			// set to 12.01 AM CST
			next := time.Date(now.Year(), now.Month(), now.Day(), 0, 1, 0, 0, loc)

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

			s.logger.Info(fmt.Sprintf("next scheduled disbursement at %s", next.Format(time.RFC3339)))

			duration := time.Until(next)
			timer := time.NewTimer(duration)
			<-timer.C

			// get allowances and check if they were updated within
			// the last 1 hour (because disbursement is weekly)
			qry := `SELECT 
						a.uuid AS allowance_uuid,
						a.username,
						a.balance,
						t.uuid AS task_uuid,
						t.is_complete,
						t.is_satisfactory,
						t.is_proactive
					FROM allowance a
						LEFT OUTER JOIN task_allowance ta ON a.uuid = ta.allowance_uuid
						LEFT OUTER JOIN task t ON ta.task_uuid = t.uuid
						LEFT OUTER JOIN template_task tt ON t.uuid = tt.task_uuid
						LEFT OUTER JOIN template tem ON tt.template_uuid = tem.uuid
					WHERE a.updated_at < ? - INTERVAL 1 HOUR
						AND a.is_active = TRUE
						AND a.is_calculated = TRUE
						AND tem.is_calculated = TRUE
						AND tem.is_archived = FALSE
						AND a.is_archived = FALSE
						AND t.created_at > ? - INTERVAL 7 DAY + INTERVAL 1 HOUR` // accounts for task creation jitter
			var records []RemittanceTask
			if err := s.sql.SelectRecords(qry, &records, now.UTC(), now.UTC()); err != nil {
				s.logger.Error(fmt.Sprintf("failed to select remittance tasks from db: %v", err))
				continue
			}

			if len(records) == 0 {
				s.logger.Info("disbursement already completed for this week, skipping")
				continue
			}

			// loop to map: allowance uuid is key, slice of remittance tasks is value
			allowances := make(map[string][]RemittanceTask, len(records))
			for _, record := range records {
				_, ok := allowances[record.AllowanceId]
				if !ok {
					allowances[record.AllowanceId] = []RemittanceTask{}
				}
				allowances[record.AllowanceId] = append(allowances[record.AllowanceId], record)
			}

			// get allowance user records from identity service
			// need birthdate to calculate the disbursement
			// get service token
			identityS2sToken, err := s.tkn.GetServiceToken(util.ServiceIdentity)
			if err != nil {
				s.logger.Error(fmt.Sprintf("/allowances post-handler failed to get service token: %s", err.Error()))
				return
			}

			// get user info from identity service --> service endpoint --> /s2s/users/groups?scopes=r:apprentice:tasks:* w:apprentice:tasks:*
			var users []profile.User
			encoded := url.QueryEscape("r:apprentice:tasks:* w:apprentice:tasks:*")
			if err := s.identity.GetServiceData(fmt.Sprintf("/s2s/users/groups?scopes=%s", encoded), identityS2sToken, "", &users); err != nil {
				s.logger.Error(fmt.Sprintf("/templates/assignees handler failed to get tasks service users from identity service: %v", err))
				return
			}

			// loop to map for easy lookup --> key is username, value is the user record
			userMap := make(map[string]profile.User, len(users))
			for _, user := range users {
				userMap[user.Username] = user
			}

			// calculate the disbursement for each allowance
			for allowance, tasks := range allowances {

				// check if tasks length is 0
				if len(tasks) < 1 {
					s.logger.Error(fmt.Sprintf("no tasks found for allowance %s", allowance))
					continue // skip this allowance calculation
				}

				// get the username and decrypt it
				// can be taken from the first task because the username is the same for all tasks
				clearUsername, err := s.cryptor.DecryptServiceData(tasks[0].Username)
				if err != nil {
					s.logger.Error(fmt.Sprintf("failed to decrypt username for allowance %s: %v", allowance, err))
					continue // skip this allowance and try the next one
				}
				username := string(clearUsername)

				// parse birthday to get age
				u := userMap[username]
				dob, err := time.Parse("2006-01-02", u.BirthDate)
				if err != nil {
					s.logger.Error(fmt.Sprintf("failed to parse %s's birthdate for allowance %s: %v", username, allowance, err))
					continue // skip this allowance and try the next one
				}

				// calculate the age in years
				age := int64(time.Since(dob).Hours() / 24 / 365)
				total := age * 100 // age is the number of dollars you get, total is in cents

				// divide the age by the number of tasks to get the disbursement per task
				// this is a simple calculation, but could be more complex in the future
				rate := total / int64(len(tasks))    // rate is in cents
				remainder := age % int64(len(tasks)) // remainder is in cents

				var earned int64 = 0
				for _, task := range tasks {

					var perTask int64 = 0
					// check if the task is complete
					if task.TaskIsComplete {
						perTask = rate
					}

					// check if the task is satisfactory
					if !task.TaskIsSatisfactory && perTask > 0 {
						perTask = perTask - (rate / 2) // lose 50% of the rate for unsatisfactory tasks
						r := rate % 2
						if r != 0 {
							perTask += r // add the remainder: calc is in cents so should be arbitrary
						}
					}

					// check if the task is proactive
					if !task.TaskIsProactive && perTask > 0 {
						perTask = perTask - (rate / 2) // lose 50% of the rate for tasks needing reminders
						r := rate % 2
						if r != 0 {
							perTask += r // add the remainder: calc is in cents so should be arbitrary
						}
					}

					// add a cent from the remainder of the rate if perTask is not 0
					if perTask > 0 && remainder > 0 {
						perTask++
						remainder--
					}

					// add the perTask (or whatever is left) to the total
					earned += perTask
				}

				// get the balance and decrypt it
				// can be taken from the first task because the balance is the same for all tasks
				clearBalance, err := s.cryptor.DecryptServiceData(tasks[0].Balance)
				if err != nil {
					s.logger.Error(fmt.Sprintf("failed to decrypt %s's balance for allowance %s: %v", username, allowance, err))
					continue // skip this allowance and try the next one
				}
				// convert decrypted balance to unsigned int64 --> balance is in cents
				balance := binary.LittleEndian.Uint64(clearBalance)

				// add the earned amount to the balance
				balance += uint64(earned)

				// convert balance to bytes for encryption
				buf := make([]byte, 8)
				binary.LittleEndian.PutUint64(buf, balance)

				// encrypt the new balance
				encBalance, err := s.cryptor.EncryptServiceData(buf)
				if err != nil {
					s.logger.Error(fmt.Sprintf("failed to encrypt %s's updated balance for allowance %s: %v", username, allowance, err))
					continue // skip this allowance and try the next one
				}

				// update the allowance balance in the db
				qry = `
						UPDATE allowance
						SET balance = ?, 
							updated_at = UTC_TIMESTAMP()
						WHERE uuid = ?`
				if err := s.sql.UpdateRecord(qry, encBalance, allowance); err != nil {
					s.logger.Error(fmt.Sprintf("failed %s's balance for allowance %s in db: %v", username, allowance, err))
					continue // skip this allowance and try the next one
				}

				s.logger.Info(fmt.Sprintf("disbursed %d cents to %s's allowance %s", earned, username, allowance))
			}
		}
	}()
}
