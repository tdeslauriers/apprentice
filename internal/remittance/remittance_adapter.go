package remittance

import (
	"database/sql"
	"time"

	"github.com/tdeslauriers/carapace/pkg/data"
)

// RemittanceRepository defines the interface for remittance data operations.
type RemittanceRepository interface {

	// FindForRemit retrieves RemittanceTasks (allowance - task joined) records for remittance processing.  Records need to be
	// active, calculated, and not updated within the last X minutes.
	// Note: these records will still be encrypted
	FindForRemit(now time.Time) ([]RemittanceTask, error)

	// UpdateBalance updates the balance of an allowance account.
	// Note: this will be a an encrypted string value representation of a number.
	UpdateBalance(balance, allowanceId string) error
}

// NewRemittanceRepository creates a new instance of RemittanceAdapter.
func NewRemittanceRepository(sql *sql.DB) RemittanceRepository {
	return &remittanceAdapter{
		sql: sql,
	}
}

var _ RemittanceRepository = (*remittanceAdapter)(nil)

// remittanceAdapter is a concrete implementation of RemittanceRepository.
type remittanceAdapter struct {
	sql *sql.DB
}

// FindForRemit retrieves RemittanceTasks (allowance - task joined) records for remittance processing.  Records need to be
// active, calculated, and not updated within the last X minutes.
// Note: these records will still be encrypted
func (a *remittanceAdapter) FindForRemit(now time.Time) ([]RemittanceTask, error) {

	qry := `
		SELECT 
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

	return data.SelectRecords[RemittanceTask](a.sql, qry, now.UTC(), now.UTC())
}

// UpdateBalance updates the balance of an allowance account.
// Note: this will be a an encrypted string value representation of a number.
func (a *remittanceAdapter) UpdateBalance(balance, allowanceId string) error {

	qry := `
		UPDATE allowance SET 
			balance = ?, 
			updated_at = UTC_TIMESTAMP()
		WHERE uuid = ?`

	return data.UpdateRecord(a.sql, qry, balance, allowanceId)
}
