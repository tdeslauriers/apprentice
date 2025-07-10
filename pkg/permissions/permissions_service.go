package permissions

import (
	"apprentice/internal/util"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tdeslauriers/carapace/pkg/data"
	"github.com/tdeslauriers/carapace/pkg/validate"
)

// Service is an interface that aggregates all permission services functionality
type Service interface {

	// GetAllPermissions returns all permissions from the database
	GetAllPermissions() ([]PermissionRecord, error)

	// GetPermissionBySlug returns a permission by its slug
	// It returns the permission or an error if the permission does not exist
	GetPermissionBySlug(slug string) (*PermissionRecord, error)

	// UpdatePermission updates an existing permission in the database, and
	// returns an error if the permission could not be updated
	UpdatePermission(p *PermissionRecord) error

	// GetUserPermissions returns the permissions for a given user/allowance account
	// returns a map of permissions and a slice of permissions so the calling function can choose which to use.
	// It returns an error if the permissions cannot be retrieved or if the user does not exist
	GetUserPermissions(username string) (map[string]PermissionRecord, []PermissionRecord, error)

	// CreatePermission creates a new permission in the database
	// It returns the created permission or an error if the permission could not be created
	CreatePermission(p *PermissionRecord) (*PermissionRecord, error)
}

// NewService creates a new Service interface, returning a pointer to the concrete implementation
func NewService(sql data.SqlRepository, i data.Indexer, c data.Cryptor) Service {
	return &service{
		db:      sql,
		indexer: i,
		cryptor: c,

		logger: slog.Default().
			With(slog.String(util.ServiceKey, util.ServiceApprentice)).
			With(slog.String(util.PackageKey, util.PackagePermissions)).
			With(slog.String(util.ComponentKey, util.ComponentPermissions)),
	}
}

var _ Service = (*service)(nil)

// service is the concrete implementation of the Service interface
type service struct {
	db      data.SqlRepository
	indexer data.Indexer
	cryptor data.Cryptor

	logger *slog.Logger
}

// GetAllPermissions is the concrete implementation of the service method which
// returns all permissions from the database.
func (s *service) GetAllPermissions() ([]PermissionRecord, error) {

	qry := `SELECT
				uuid,
				service_name,
				permission,
				name,
				description,
				created_at,
				active,
				slug,
				slug_index
			FROM permission`
	var ps []PermissionRecord
	if err := s.db.SelectRecords(qry, &ps); err != nil {
		return nil, fmt.Errorf("failed to get permissions: %v", err)
	}

	if len(ps) < 1 {
		s.logger.Warn("no permissions found in database")
	}

	// decrypt permissions
	for i, p := range ps {
		prepared, err := s.decryptPermission(p)
		if err != nil {
			return nil, fmt.Errorf("failed to prepare permission %s: %v", p.Id, err)
		}
		ps[i] = *prepared
	}

	return ps, nil
}

// GetUserPermissions is the concrete implementation of the service method which
// returns the permissions for a given user/allowance account.
// It returns a map of permissions and a slice of permissions so the calling
// function can choose which to use.
// It returns an error if the permissions cannot be retrieved or if the user does not exist
func (s *service) GetUserPermissions(username string) (map[string]PermissionRecord, []PermissionRecord, error) {

	// validate is well formed email address: redundant, but good practice.
	if err := validate.IsValidEmail(username); err != nil {
		return nil, nil, err
	}

	// get blind index for user in allowance table
	index, err := s.indexer.ObtainBlindIndex(username)
	if err != nil {
		return nil, nil, err
	}

	// get permissions for user in allowance table
	query := `SELECT
				p.uuid,
				p.service_name,
				p.permission,
				p.name,
				p.description,
				p.created_at,
				p.active,
				p.slug,
				p.slug_index
			FROM permission p
				LEFT OUTER JOIN allowance_permission ap ON p.uuid = ap.permission_uuid
				LEFT OUTER JOIN allowance a ON ap.allowance_uuid = a.uuid
			WHERE a.user_index = ?
				AND p.active = true`
	var ps []PermissionRecord
	if err := s.db.SelectRecords(query, &ps, index); err != nil {
		return nil, nil, err
	}

	if len(ps) < 1 {
		return nil, nil, fmt.Errorf("no permissions found for user %s", username)
	}

	// decrypt and create a map of permissions
	psMap := make(map[string]PermissionRecord, len(ps))
	for i, p := range ps {
		prepared, err := s.decryptPermission(p)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to prepare permission %s: %v", p.Id, err)
		}
		ps[i] = *prepared
		psMap[p.Name] = *prepared
	}

	// return the permissions
	return psMap, ps, nil
}

// GetPermissionBySlug is the concrete implementation of the service method which
// returns a permission by its slug.
func (s *service) GetPermissionBySlug(slug string) (*PermissionRecord, error) {
	// validate slug
	if !validate.IsValidUuid(slug) {
		return nil, fmt.Errorf("invalid slug: %s", slug)
	}

	// get blind index for slug
	index, err := s.indexer.ObtainBlindIndex(slug)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain blind index for slug '%s': %v", slug, err)
	}

	// build the query to get the permission by slug
	query := `SELECT
				p.uuid,
				p.service_name,
				p.permission,
				p.name,
				p.description,
				p.created_at,
				p.active,
				p.slug,
				p.slug_index
			FROM permission p
			WHERE p.slug_index = ?`
	var record PermissionRecord
	if err := s.db.SelectRecord(query, &record, index); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("permission with slug '%s' not found", slug)
		}
		return nil, fmt.Errorf("failed to get permission by slug '%s': %v", slug, err)
	}

	// decrypt the permission record
	p, err := s.decryptPermission(record)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare permission %s: %v", record.Id, err)
	}

	return p, nil
}

// CreatePermission is the concrete implementation of the service method which
// creates a new permission in the database.
// It returns the created permission or an error if the permission could not be created
func (s *service) CreatePermission(p *PermissionRecord) (*PermissionRecord, error) {

	// validate the permission
	// redundant, but good practice.
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid permission: %v", err)
	}

	// create uuid and set it in the permission record
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to create uuid for permission: %v", err)
	}
	p.Id = id.String()

	// create created_at timestamp and set it in the permission record
	now := time.Now().UTC()
	p.CreatedAt = data.CustomTime{Time: now}

	// create slug and set it in the permission record
	slug, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to create slug for permission: %v", err)
	}
	p.Slug = slug.String()

	// create slug index and set it in the permission record
	idx, err := s.indexer.ObtainBlindIndex(slug.String())
	if err != nil {
		return nil, fmt.Errorf("failed to obtain blind index for slug '%s': %v", slug.String(), err)
	}
	p.SlugIndex = idx

	// encrypt the permission record
	record, err := s.encryptPermission(p)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt permission: %v", err)
	}

	// build the insert query
	query := `INSERT INTO permission (
				uuid,
				service_name,
				permission,
				name,
				description,
				created_at,
				active,
				slug,
				slug_index
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if err := s.db.InsertRecord(query, *record); err != nil {
		return nil, fmt.Errorf("failed to create permission: %v", err)
	}

	s.logger.Info(fmt.Sprintf("%s - %s created", p.Id, p.Name))

	// p remains unencrypted, so it may be returned.
	// remove the index as it is not needed in the response
	p.SlugIndex = "" // clear slug index as it is not needed in the response

	return p, nil
}

// UpdatePermission is the concrete implementation of the service method which
// updates an existing permission in the database, and
// returns an error if the permission could not be updated
func (s *service) UpdatePermission(p *PermissionRecord) error {

	// validate the permission
	// redundant, but good practice.
	if err := p.Validate(); err != nil {
		return fmt.Errorf("invalid permission: %v", err)
	}

	// encrypt permission record for storage
	r, err := s.encryptPermission(p)
	if err != nil {
		return fmt.Errorf("failed to encrypt permission: %v", err)
	}

	// build the update query
	query := `UPDATE permission SET
				permission = ?,
				name = ?,
				description = ?,
				active = ?,
				slug = ?
			WHERE uuid = ?`
	if err := s.db.UpdateRecord(query, r.Permission, r.Name, r.Description, r.Active, r.Slug, r.Id); err != nil {
		return fmt.Errorf("failed to update permission: %v", err)
	}

	s.logger.Info(fmt.Sprintf("permission record %s - %s updated", p.Id, p.Name))

	return nil
}

// decryptPermission is a helper method that decrypts sensitive fields
// and removes uncessary fields in the permission data model.
func (s *service) decryptPermission(p PermissionRecord) (*PermissionRecord, error) {

	var (
		wg     sync.WaitGroup
		pmCh   = make(chan string, 1)
		nameCh = make(chan string, 1)
		descCh = make(chan string, 1)
		slugCh = make(chan string, 1)
		errCh  = make(chan error, 4)
	)

	wg.Add(4)
	go s.decrypt("permission", p.Permission, pmCh, errCh, &wg)
	go s.decrypt("name", p.Name, nameCh, errCh, &wg)
	go s.decrypt("description", p.Description, descCh, errCh, &wg)
	go s.decrypt("slug", p.Slug, slugCh, errCh, &wg)

	wg.Wait()
	close(pmCh)
	close(nameCh)
	close(descCh)
	close(slugCh)
	close(errCh)

	// check for errors during decryption
	if len(errCh) > 0 {
		var errs []error
		for e := range errCh {
			errs = append(errs, e)
		}
		if len(errs) > 0 {
			return nil, errors.Join(errs...)
		}
	}

	p.Permission = <-pmCh
	p.Name = <-nameCh
	p.Description = <-descCh
	p.Slug = <-slugCh
	p.SlugIndex = "" // clear slug index as it is not needed in the response

	return &p, nil
}

func (s *service) decrypt(fieldname, encrpyted string, fieldCh chan string, errCh chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	// decrypt service data
	decrypted, err := s.cryptor.DecryptServiceData(encrpyted)
	if err != nil {
		errCh <- fmt.Errorf("failed to decrypt '%s' field: %v", fieldname, err)
	}

	fieldCh <- string(decrypted)
}

// encryptPermission is a helper method that encrypts sensitive fields
// in the permission data model, preparing the record for storage in the database.
func (s *service) encryptPermission(p *PermissionRecord) (*PermissionRecord, error) {

	var (
		wg     sync.WaitGroup
		pmCh   = make(chan string, 1)
		nameCh = make(chan string, 1)
		descCh = make(chan string, 1)
		slugCh = make(chan string, 1)
		errCh  = make(chan error, 4)
	)

	wg.Add(4)
	go s.encrypt("permission", p.Permission, pmCh, errCh, &wg)
	go s.encrypt("name", p.Name, nameCh, errCh, &wg)
	go s.encrypt("description", p.Description, descCh, errCh, &wg)
	go s.encrypt("slug", p.Slug, slugCh, errCh, &wg)

	wg.Wait()
	close(pmCh)
	close(nameCh)
	close(descCh)
	close(slugCh)
	close(errCh)

	// check for errors during encryption
	if len(errCh) > 0 {
		var errs []error
		for e := range errCh {
			errs = append(errs, e)
		}
		if len(errs) > 0 {
			return nil, errors.Join(errs...)
		}
	}

	encrypted := &PermissionRecord{
		Id:          p.Id,
		ServiceName: p.ServiceName,
		Permission:  <-pmCh,
		Name:        <-nameCh,
		Description: <-descCh,
		CreatedAt:   p.CreatedAt,
		Active:      p.Active,
		Slug:        <-slugCh,
		SlugIndex:   p.SlugIndex, // slug index is not encrypted, is hash
	}

	return encrypted, nil
}

// encrypt is a helper method that encrypts sensitive fields in the permission data model.
func (s *service) encrypt(field, plaintext string, fieldCh chan string, errCh chan error, wg *sync.WaitGroup) {

	defer wg.Done()

	// encrypt service data
	encrypted, err := s.cryptor.EncryptServiceData([]byte(plaintext))
	if err != nil {
		errCh <- fmt.Errorf("failed to encrypt '%s' field: %v", field, err)
		return
	}

	fieldCh <- string(encrypted)
}
