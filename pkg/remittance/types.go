package remittance

// RemittanceTask is a model for a remittance task record which is used to calculate disbursement
type RemittanceTask struct {
	AllowanceId        string `db:"allowance_uuid" json:"id,omitempty"`
	Username           string `db:"username" json:"username"`
	Balance            string `db:"balance" json:"balance"`
	TaskId             string `db:"task_uuid" json:"task_id"`
	TaskIsComplete     bool   `db:"is_complete" json:"is_complete"`
	TaskIsSatisfactory bool   `db:"is_satisfactory" json:"is_satisfactory"`
	TaskIsProactive    bool   `db:"is_proactive" json:"is_proactive"`
}
