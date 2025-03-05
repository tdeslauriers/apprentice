package allowances

import (
	"apprentice/internal/util"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/tasks"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// AllowanceService is the interface for the allowances service functionality
type AllowanceService interface {

	// CreateAllowance creates a new allowance account for a user
	CreateAllowance(username string) (*tasks.Allowance, error)
}

// NewAllowanceService creates a new Service interface, returning a pointer to the concrete implementation
func NewAllowanceService(sql data.SqlRepository, i data.Indexer, c data.Cryptor) AllowanceService {
	return &allowanceService{
		sql:     sql,
		indexer: i,
		cryptor: c,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackageAllowances)).
			With(slog.String(util.ComponentKey, util.ComponentAllowances)),
	}
}

var _ AllowanceService = (*allowanceService)(nil)

// allowanceService is the concrete implementation of the Service interface
type allowanceService struct {
	sql     data.SqlRepository
	indexer data.Indexer
	cryptor data.Cryptor

	logger *slog.Logger
}

// CreateAllowance is the concrete implementation of the Service interface method CreateAllowance
// Note: consolidationg account exists? check since the index would need to be generated twice otherwise.
func (s *allowanceService) CreateAllowance(username string) (*tasks.Allowance, error) {

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
	qryExists := `SELECT EXISTS(SELECT 1 FROM allowance WHERE user_index = ?) AS record_exists`
	exists, err := s.sql.SelectExists(qryExists, userIndex)
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
	errCount := len(chErr)
	if errCount > 0 {
		var sb strings.Builder
		counter := 0
		for e := range chErr {
			sb.WriteString(e.Error())
			if counter < errCount-1 {
				sb.WriteString("; ")
			}
			counter++
		}
		return nil, fmt.Errorf(sb.String())
	}

	// prepare record for db insertion
	// Note: this model has all values as strings due to encryption.
	// types.Allowance model has balance as a float64
	record := AllowanceRecord{
		Id:           allowanceId,
		Balance:      balance,
		Username:     user,
		UserIndex:    userIndex,
		Slug:         encryptedSlug,
		SlugIndex:    allowanceIndex,
		CreatedAt:    data.CustomTime{Time: time.Now().UTC()},
		IsArchived:   false,
		IsActive:     true,
		IsCalculated: true,
	}

	// insert record into db
	qry := `
		INSERT INTO allowance (
			uuid, 
			balance, 
			username, 
			user_index, 
			slug, 
			slug_index, 
			created_at, 
			is_archived, 
			is_active, 
			is_calculated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if err := s.sql.InsertRecord(qry, record); err != nil {
		return nil, fmt.Errorf("failed to insert new allowance account record into database for username %s: %v", username, err)
	}

	s.logger.Info(fmt.Sprintf("successfully persisted new allowance account record to database for username %s", username))

	// return clear text allowance account model
	return &tasks.Allowance{
		Id:           allowanceId,
		Balance:      0.0,
		Username:     username,
		Slug:         allowanceSlug,
		CreatedAt:    record.CreatedAt,
		IsArchived:   false,
		IsActive:     true,
		IsCalculated: true,
	}, nil
}
