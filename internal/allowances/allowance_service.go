package allowances

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/apprentice/internal/permissions"
	"github.com/tdeslauriers/apprentice/internal/util"
	"github.com/tdeslauriers/apprentice/pkg/api/allowances"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// AllowanceService is the interface for the allowances service functionality
type AllowanceService interface {

	// GetAllowances returns all allowance accounts
	GetAllowances() ([]allowances.Allowance, error)

	// GetBySlug returns a single allowance account by slug
	GetBySlug(slug string) (*allowances.Allowance, error)

	// GetByUser returns a single allowance account by username
	GetByUser(username string) (*allowances.Allowance, error)

	// GetByUsers returns multiple allowance accounts by usernames if they are valid.
	// and returns a slice of the users names that were not found in the database.
	// Note: it will error on any not well-formed usernames.
	GetValidUsers(users []string) (existing []allowances.Allowance, missing []string, err error)

	// CreateAllowance creates a new allowance account for a user
	CreateAllowance(username string) (*allowances.Allowance, error)

	// ValidateUpdate validates the update command for an allowance account for business rules errors.
	// Note: this is in-addition-to struct field validation checks.
	ValidateUpdate(cmd allowances.UpdateAllowanceCmd, record allowances.Allowance) error

	// UpdateAllowance updates an allowance account
	UpdateAllowance(cmd *allowances.Allowance) error
}

// NewAllowanceService creates a new Service interface, returning a pointer to the concrete implementation
func NewAllowanceService(sql *sql.DB, i data.Indexer, c data.Cryptor) AllowanceService {
	return &allowanceService{
		sql:        NewAllowanceRepository(sql),
		indexer:    i,
		cryptor:    c,
		permission: permissions.NewService(sql, i, c),

		logger: slog.Default().
			With(slog.String(util.PackageKey, util.PackageAllowances)).
			With(slog.String(util.ComponentKey, util.ComponentAllowances)),
	}
}

var _ AllowanceService = (*allowanceService)(nil)

// allowanceService is the concrete implementation of the Service interface
type allowanceService struct {
	sql        AllowanceRepository
	indexer    data.Indexer
	cryptor    data.Cryptor
	permission permissions.Service

	logger *slog.Logger
}

// GetAllowances is the concrete implementation of the Service interface method GetAll
func (s *allowanceService) GetAllowances() ([]allowances.Allowance, error) {

	// get all allowance accounts
	records, err := s.sql.FindAll()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve all allowance accounts: %v", err)
	}

	// decrypt and convert to clear text model; drop unneeded fields
	var (
		wg            sync.WaitGroup
		allowanceChan = make(chan allowances.Allowance, len(records))
		chErr         = make(chan error, len(records))
	)

	for _, record := range records {
		wg.Add(1)
		go func(r AllowanceRecord, ch chan allowances.Allowance, chErr chan error, wg *sync.WaitGroup) {

			defer wg.Done()

			a, err := s.prepareAllowance(r)
			if err != nil {
				chErr <- fmt.Errorf("failed to prepare allowance account %s: %v", r.Id, err)
				return
			}

			ch <- *a

		}(record, allowanceChan, chErr, &wg)
	}

	// wait for goroutines to complete
	wg.Wait()
	close(allowanceChan)
	close(chErr)

	// check for errors

	if len(chErr) > 0 {
		var errs []error
		for e := range chErr {
			errs = append(errs, e)
		}
		return nil, fmt.Errorf("failed to prepare allowance accounts: %v", errors.Join(errs...))
	}

	// collect clear text models
	var allowances []allowances.Allowance
	for a := range allowanceChan {
		allowances = append(allowances, a)
	}

	return allowances, nil
}

// GetBySlug is the concrete implementation of the Service interface method GetBySlug
func (s *allowanceService) GetBySlug(slug string) (*allowances.Allowance, error) {

	// validate slug
	if !validate.IsValidUuid(slug) {
		return nil, fmt.Errorf("%s: %s", ErrInvalidAllowanceSlug, slug)
	}

	// get blind index for slug
	index, err := s.indexer.ObtainBlindIndex(slug)
	if err != nil {
		return nil, fmt.Errorf("%s for slug %s: %v", ErrGenIndex, slug, err)
	}

	// get allowance account
	record, err := s.sql.FindBySlugIndex(index)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve allowance account for slug %s: %v", slug, err)
	}

	// decrypt and convert to clear text model
	a, err := s.prepareAllowance(*record)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt/prepare allowance account %s: %v", record.Id, err)
	}

	// get permissions for allowance account
	_, ps, err := s.permission.GetAllowancePermissions(a.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions for allowance account %s: %v", a.Id, err)
	}

	a.Permissions = ps

	return a, nil
}

// GetByUser is the concrete implementation of the Service interface method GetByUser
func (s *allowanceService) GetByUser(username string) (*allowances.Allowance, error) {

	// validate username
	if err := validate.IsValidEmail(username); err != nil {
		return nil, fmt.Errorf("%s: %v", ErrInvalidUsername, err)
	}

	// get blind index for username
	index, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, fmt.Errorf("%s for username %s: %v", ErrGenIndex, username, err)
	}

	// get allowance account
	record, err := s.sql.FindByUserIndex(index)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("%s for username %s", ErrAllowanceNotFound, username)
		}
		return nil, fmt.Errorf("failed to retrieve allowance account for username %s: %v", username, err)
	}

	// decrypt and convert to clear text model
	a, err := s.prepareAllowance(*record)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt/prepare allowance account %s: %v", record.Id, err)
	}

	// get permissions for allowance account
	_, ps, err := s.permission.GetAllowancePermissions(a.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions for allowance account %s: %v", a.Id, err)
	}

	a.Permissions = ps

	return a, nil
}

// GetValidUsers is the concrete implementation of the Service interface method GetValidUsers
// It will error if any of the users does not exist in the database.
func (s *allowanceService) GetValidUsers(users []string) ([]allowances.Allowance, []string, error) {

	// handle empty input
	if len(users) == 0 {
		return nil, nil, errors.New("users slice cannot be empty.")
	}

	// validate usernames
	for _, user := range users {
		if err := validate.IsValidEmail(user); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", ErrInvalidUsername, err)
		}
	}

	// get blind userIndexes for usernames
	userIndexes := make([]string, len(users))
	for i, user := range users {
		ind, err := s.indexer.ObtainBlindIndex(user)
		if err != nil {
			return nil, nil, fmt.Errorf("%s for username %s: %w", ErrGenIndex, user, err)
		}
		userIndexes[i] = ind
	}

	// get allowance accounts
	// Note: userindexes that do not exist will not be returned, ie, ignored.
	records, err := s.sql.FindUsersByIndices(userIndexes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve allowance accounts for users: %w", err)
	}

	// decrypt and convert to clear text models
	var (
		wg          sync.WaitGroup
		allowanceCh = make(chan allowances.Allowance, len(records))
		chErr       = make(chan error, len(records))
	)

	for _, record := range records {
		wg.Add(1)
		go func(r AllowanceRecord, ch chan allowances.Allowance, chErr chan error, wg *sync.WaitGroup) {

			defer wg.Done()

			a, err := s.prepareAllowance(r)
			if err != nil {
				chErr <- fmt.Errorf("failed to prepare allowance account %s: %w", r.Id, err)
				return
			}

			ch <- *a

		}(record, allowanceCh, chErr, &wg)
	}

	// wait for goroutines to complete
	wg.Wait()
	close(allowanceCh)
	close(chErr)

	// check for errors
	if len(chErr) > 0 {
		errs := make([]string, 0, len(chErr))
		for e := range chErr {
			errs = append(errs, e.Error())
		}
		return nil, nil, fmt.Errorf("failed to prepare allowance accounts: %v", strings.Join(errs, "; "))
	}

	// collect existing users into a map
	found := make(map[string]allowances.Allowance, len(allowanceCh)) // username is the key
	for a := range allowanceCh {
		found[a.Username] = a
	}

	// Compare found to orginal user list
	existing := make([]allowances.Allowance, 0, len(users))
	missing := make([]string, 0, len(users))
	for _, u := range users {
		if _, ok := found[u]; !ok {
			missing = append(missing, u)
		} else {
			existing = append(existing, found[u])
		}
	}

	return existing, missing, nil
}

// CreateAllowance is the concrete implementation of the Service interface method CreateAllowance
// Note: consolidationg account exists? check since the index would need to be generated twice otherwise.
func (s *allowanceService) CreateAllowance(username string) (*allowances.Allowance, error) {

	// check if username is valid email
	if err := validate.IsValidEmail(username); err != nil {
		return nil, fmt.Errorf("%s: %v", ErrInvalidUsername, err)
	}

	// generate username userIndex
	userIndex, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, fmt.Errorf("%s from username %s: %v", ErrGenIndex, username, err)
	}

	// check if account record exists --> decryption not necessary
	exists, err := s.sql.FindExistsByUser(userIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to check if account record exists for username %s: %v", username, err)
	}
	if exists {
		return nil, fmt.Errorf("%s for username %s", ErrAccountExists, username)
	}

	//create account record

	var (
		allowanceId    string
		balance        string // encrypted balance --> float64 to string
		user           string // encrypted username
		allowanceSlug  string
		encryptedSlug  string
		allowanceIndex string

		wg    sync.WaitGroup
		chErr = make(chan error, 4)
	)

	// generate uuid for allowance account
	wg.Add(1)
	go func(id *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()
		i, err := uuid.NewRandom()
		if err != nil {
			ch <- fmt.Errorf("failed to generate uuid username's %s allowance account: %v", username, err)
		}

		*id = i.String()
	}(&allowanceId, chErr, &wg)

	// inialize and ecrypt balance
	wg.Add(1)
	go func(encrypted *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		// initialize balance to 0.0
		bal := 0.0

		// convert to byte slice
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, math.Float64bits(bal))

		enc, err := s.cryptor.EncryptServiceData(buf)
		if err != nil {
			ch <- fmt.Errorf("failed to encrypt initial balance for allowance account creation: %v", err)
		}

		*encrypted = enc

	}(&balance, chErr, &wg)

	// encrypt username
	wg.Add(1)
	go func(encrypted *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		enc, err := s.cryptor.EncryptServiceData([]byte(username))
		if err != nil {
			ch <- fmt.Errorf("failed to encrypt username %s for allowance account creation: %v", username, err)
		}

		*encrypted = enc

	}(&user, chErr, &wg)

	// generate allowance slug, encrypted slug + index
	wg.Add(1)
	go func(slug, encrypted, index *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		// generate slug
		slg, err := uuid.NewRandom()
		if err != nil {
			ch <- fmt.Errorf("failed to generate slug for allownance account creation for username %s: %v", username, err)
		}

		*slug = slg.String()

		// encrypt slug
		enc, err := s.cryptor.EncryptServiceData([]byte(slg.String()))
		if err != nil {
			ch <- fmt.Errorf("failed to encrypt slug for allownance account creation for username %s: %v", username, err)
		}

		*encrypted = enc

		// generate index
		ind, err := s.indexer.ObtainBlindIndex(slg.String())
		if err != nil {
			ch <- fmt.Errorf("%s for slug for allownance account creation for username %s: %v", ErrGenIndex, username, err)
		}

		*index = ind
	}(&allowanceSlug, &encryptedSlug, &allowanceIndex, chErr, &wg)

	// wait for goroutines to complete
	wg.Wait()
	close(chErr)

	// check for errors
	if len(chErr) > 0 {
		var errs []error
		for e := range chErr {
			errs = append(errs, e)
		}
		return nil, fmt.Errorf("failed to generate allowance account data %s: %v", username, errors.Join(errs...))
	}

	// prepare record for db insertion
	// Note: this model has all values as strings due to encryption.
	// types.Allowance model has balance as a float64
	now := time.Now().UTC()
	record := AllowanceRecord{
		Id:           allowanceId,
		Balance:      balance,
		Username:     user,
		UserIndex:    userIndex,
		Slug:         encryptedSlug,
		SlugIndex:    allowanceIndex,
		CreatedAt:    data.CustomTime{Time: now},
		UpdatedAt:    data.CustomTime{Time: now},
		IsArchived:   false,
		IsActive:     true,
		IsCalculated: true,
	}

	// insert record into db
	if err := s.sql.InsertAllowance(record); err != nil {
		return nil, fmt.Errorf("failed to insert new allowance account record into database for username %s: %v",
			username, err)
	}

	// return clear text allowance account model
	return &allowances.Allowance{
		Id:       allowanceId,
		Balance:  0.0,
		Username: username,
		Slug:     allowanceSlug,
		CreatedAt: data.CustomTime{
			Time: time.Now().UTC(),
		},
		IsArchived:   false,
		IsActive:     true,
		IsCalculated: true,
	}, nil
}

// UpdateAllowance is the concrete implementation of the Service interface method UpdateAllowance
// Note: this function updates the allowance fields, not the assigned (user or slug).  The user is immutable.
// If a new user should be assigned to the account, a new account should be created.
// This may need to be re-evaluated later.
func (s *allowanceService) UpdateAllowance(cmd *allowances.Allowance) error {

	// validate slug: redundant check, but good practice in case this is called by a different function
	if !validate.IsValidUuid(cmd.Slug) {
		return fmt.Errorf("%s: %s", ErrInvalidAllowanceSlug, cmd.Slug)
	}

	// get blind index for slug
	index, err := s.indexer.ObtainBlindIndex(cmd.Slug)
	if err != nil {
		return fmt.Errorf("%s for allowance slug %s: %v", ErrGenIndex, cmd.Slug, err)
	}

	// convert balance to bytes for encryption
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, cmd.Balance)

	// encrypt balance
	encBal, err := s.cryptor.EncryptServiceData(buf)
	if err != nil {
		return fmt.Errorf("failed to encrypt balance for updating allowance account id %s, slug %s: %v",
			cmd.Id, cmd.Slug, err)
	}

	// update account record
	if err := s.sql.UpdateAllowance(AllowanceRecord{
		Balance:      encBal,           // to update
		SlugIndex:    index,            // for lookup/WHERE clause
		UpdatedAt:    cmd.UpdatedAt,    // to update
		IsArchived:   cmd.IsArchived,   // to update
		IsActive:     cmd.IsActive,     // to update
		IsCalculated: cmd.IsCalculated, // to update
	}); err != nil {
		return fmt.Errorf("failed to update allowance account record for id %s, slug %s: %v",
			cmd.Id, cmd.Slug, err)
	}

	return nil
}

// prepareAllowance decrypts and converts an allowance record to a clear text model
func (s *allowanceService) prepareAllowance(r AllowanceRecord) (*allowances.Allowance, error) {

	var (
		wg    sync.WaitGroup
		chErr = make(chan error, 3)

		// clear text fields
		balance  uint64
		username string
		slug     string
	)

	// decrypt balance
	wg.Add(1)
	go func(b *uint64, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		dec, err := s.cryptor.DecryptServiceData(r.Balance)
		if err != nil {
			ch <- fmt.Errorf("failed to decrypt balance for allowance account %s: %v", r.Id, err)
		}

		// convert decrypted balance
		bal := binary.LittleEndian.Uint64(dec)

		*b = bal
	}(&balance, chErr, &wg)

	// decrypt username
	wg.Add(1)
	go func(u *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		dec, err := s.cryptor.DecryptServiceData(r.Username)
		if err != nil {
			ch <- fmt.Errorf("failed to decrypt username for allowance account %s: %v", r.Id, err)
		}

		// convert decrypted username to string
		*u = string(dec)
	}(&username, chErr, &wg)

	// decrypt slug
	wg.Add(1)
	go func(sg *string, ch chan error, wg *sync.WaitGroup) {
		defer wg.Done()

		dec, err := s.cryptor.DecryptServiceData(r.Slug)
		if err != nil {
			ch <- fmt.Errorf("failed to decrypt slug for allowance account %s: %v", r.Id, err)
		}

		// convert decrypted slug to string
		*sg = string(dec)
	}(&slug, chErr, &wg)

	// wait for goroutines to complete
	wg.Wait()
	close(chErr)

	// check for errors
	if len(chErr) > 0 {
		var errs []error
		for e := range chErr {
			errs = append(errs, e)
		}
		return nil, fmt.Errorf("errors occurred during allowance account decryption: %v", errors.Join(errs...))
	}

	// return clear text model
	// omitting fields: userIndex, slugIndex
	return &allowances.Allowance{
		Id:           r.Id,
		Balance:      balance,
		Username:     username,
		Slug:         slug,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
		IsArchived:   r.IsArchived,
		IsActive:     r.IsActive,
		IsCalculated: r.IsCalculated,
	}, nil
}

// ValidateUpdate is the concrete implementation of the Service interface method ValidateUpdate
// Note: this is not written in a consise way, but rather to show the logic more explicitly
// and includes redundant checks for in case the input validation check is not performed.
func (s *allowanceService) ValidateUpdate(cmd allowances.UpdateAllowanceCmd, record allowances.Allowance) error {

	// check for valid debit and credit amounts
	if cmd.Debit > 1000000 {
		return fmt.Errorf("invalid debit: cannot debit more than $10,000 because that is ridiculous")
	}

	if cmd.Credit > 1000000 {
		return fmt.Errorf("invalid credit: cannot credit more than $10,000 because that is ridiculous")
	}

	// make sure account is not archived, active and calculated to update the balance
	if cmd.Credit > 0 || cmd.Debit > 0 {

		if cmd.IsArchived {
			return fmt.Errorf("invalid balance update: cannot update balance of an archived account")
		}

		if !cmd.IsActive {
			return fmt.Errorf("invalid balance update: cannot update balance of an inactive account")
		}

		if !cmd.IsCalculated {
			return fmt.Errorf("invalid balance update: cannot update balance of an uncalculated account")
		}
	}

	// check the balance does not become negative
	if cmd.Debit > cmd.Credit+record.Balance {
		return fmt.Errorf("invalid debit: cannot debit more than the current balance + credit")
	}

	// checks required if the account is being set to archived
	if cmd.IsArchived {

		// make sure balance is not also being updated
		if cmd.Debit > 0 || cmd.Credit > 0 {
			return fmt.Errorf("invalid selection: cannot set account to archived and update balance at the same time")
		}

		// cannot set it to inactive or calculated at the same time
		if cmd.IsActive || cmd.IsCalculated {
			return fmt.Errorf("invalid selection: cannot set account to archived and inactive or uncalculated at the same time")
		}
	}

	// !cmd.IsArchived does not have rules.

	// checks required if the account is being set to active
	if cmd.IsActive {

		// cannot set it to archived at the same time
		if cmd.IsArchived {
			return fmt.Errorf("invalid selection: cannot set account to active and archived at the same time")
		}
	}

	if !cmd.IsActive {

		// cannot set it to calculeated
		if cmd.IsCalculated {
			return fmt.Errorf("invalid selection: cannot set account to inactive and calculated at the same time")
		}
	}

	// checks required if the account is being set to calculated
	if cmd.IsCalculated {

		// cannot set it to archived at the same time
		if cmd.IsArchived {
			return fmt.Errorf("invalid selection: cannot set account to calculated and archived at the same time")
		}

		if !cmd.IsActive {
			return fmt.Errorf("invalid selection: cannot set account to calculated and inactive at the same time")
		}

	}
	return nil

}
