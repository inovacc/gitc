package platform

import (
	"context"
	"database/sql"
	"errors"
	"os"

	"github.com/inovacc/gitc/internal/db"
)

// Platform holds shared infrastructure connections.
type Platform struct {
	DB *sql.DB
}

// New initialises all configured backends from environment variables.
func New(ctx context.Context) (*Platform, error) {
	p := &Platform{}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "file:gitc.db"
	}
	sqlDB, err := db.New(dsn)
	if err != nil {
		return nil, err
	}
	p.DB = sqlDB
	return p, nil
}

// Close releases all backend connections.
func (p *Platform) Close(_ context.Context) error {
	var errs []error
	if p.DB != nil {
		if err := p.DB.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
