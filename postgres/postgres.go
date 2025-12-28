// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package postgres

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	pg "gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	pgDSN          string
	pgDBName       string
	pgTables       []interface{}
	pgConn         *gorm.DB
	pgLock         = sync.Mutex{}
	testDBFile     = "test.db"
	useEmulator    = false
	verboseLogging = false
	dbCreated      = false

	ErrInvalidDSNOrDBName  = errors.New("invalid dsn or db name")
)

// Custom logger that triggers diagnostics on slow SQL
type slowSQLLogger struct {
	logger.Interface
	slowThreshold time.Duration
	diagOnce      sync.Once
}

func newSlowSQLLogger(slowThreshold time.Duration) *slowSQLLogger {
	return &slowSQLLogger{
		Interface: logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{
			SlowThreshold:             slowThreshold,
			LogLevel:                  logger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  true,
		}),
		slowThreshold: slowThreshold,
	}
}

func (l *slowSQLLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	elapsed := time.Since(begin)
	sql, rows := fc()

	// Call the underlying logger's Trace
	l.Interface.Trace(ctx, begin, fc, err)

	// Trigger diagnostics on slow SQL
	if elapsed > l.slowThreshold {
		log.Printf("SLOW SQL DETECTED: %v elapsed for query: %s (rows: %d)", elapsed, sql, rows)

		// Run diagnostics once per slow query session
		l.diagOnce.Do(func() {
			// go runSlowSQLDiagnostics()
		})
	}
}

func runSlowSQLDiagnostics() {
	log.Println("=== SLOW SQL DIAGNOSTICS START ===")

	if pgConn == nil {
		log.Println("DIAG: pgConn is nil")
		return
	}

	sqlDB, err := pgConn.DB()
	if err != nil {
		log.Printf("DIAG: Failed to get sql.DB: %v", err)
		return
	}

	// 1. Connection pool stats
	stats := sqlDB.Stats()
	log.Printf("DIAG Pool Stats: Open=%d InUse=%d Idle=%d WaitCount=%d WaitDuration=%v MaxOpen=%d MaxIdle=%d",
		stats.OpenConnections,
		stats.InUse,
		stats.Idle,
		stats.WaitCount,
		stats.WaitDuration,
		stats.MaxOpenConnections,
		stats.MaxIdleTimeClosed)

	// 2. Test raw ping latency
	for i := 0; i < 3; i++ {
		start := time.Now()
		err := sqlDB.Ping()
		log.Printf("DIAG Ping %d: %v (err: %v)", i, time.Since(start), err)
	}

	// 3. Test raw SQL query (bypass GORM)
	for i := 0; i < 3; i++ {
		start := time.Now()
		rows, err := sqlDB.Query("SELECT 1")
		duration := time.Since(start)
		if rows != nil {
			rows.Close()
		}
		log.Printf("DIAG Raw SQL %d: %v (err: %v)", i, duration, err)
	}

	// 4. Test GORM query with struct condition (SLOW?)
	for i := 0; i < 3; i++ {
		start := time.Now()
		var wgInfo struct {
			ID     string
			NodeID uint64
		}
		nodeID := uint64(38084)
		pgConn.Table("wg_infos").Where(&struct{ NodeID *uint64 }{NodeID: &nodeID}).Take(&wgInfo)
		log.Printf("DIAG GORM struct condition %d: %v", i, time.Since(start))
	}

	// 5. Test GORM query with explicit WHERE (FAST?)
	for i := 0; i < 3; i++ {
		start := time.Now()
		var wgInfo struct {
			ID     string
			NodeID uint64
		}
		pgConn.Table("wg_infos").Where("node_id = ?", 38084).Take(&wgInfo)
		log.Printf("DIAG GORM explicit WHERE %d: %v", i, time.Since(start))
	}

	// 6. Test raw SQL on wg_infos
	for i := 0; i < 3; i++ {
		start := time.Now()
		rows, err := sqlDB.Query("SELECT id, node_id FROM wg_infos WHERE node_id = 38084 LIMIT 1")
		duration := time.Since(start)
		if rows != nil {
			rows.Close()
		}
		log.Printf("DIAG Raw wg_infos query %d: %v (err: %v)", i, duration, err)
	}

	log.Println("=== SLOW SQL DIAGNOSTICS END ===")
}

// Manual diagnostics function that can be called externally
func DiagnoseDBLatency() {
	runSlowSQLDiagnostics()
}

// Reset diagnostics trigger (useful for testing)
func ResetDiagnostics() {
	if l, ok := pgConn.Logger.(*slowSQLLogger); ok {
		l.diagOnce = sync.Once{}
	}
}

func Init(dsn, dbName string, tables []interface{}) error {
	if dsn == "" || dbName == "" {
		return ErrInvalidDSNOrDBName
	}
	pgDSN = dsn
	pgDBName = dbName
	pgTables = tables
	return nil
}

func CleanupEmulator() {
	os.Remove(testDBFile)
}

func newConn(dsn string) (*gorm.DB, error) {
	var err error
	if useEmulator {
		pgConn = newSqliteConn()
		return pgConn, err
	}
	autoMigrate := false
	if !dbCreated {
		if err := CheckAndCreatedDB(); err != nil {
			return nil, err
		}
		autoMigrate = true
	}

	// Use custom slow SQL logger
	customLogger := newSlowSQLLogger(100 * time.Millisecond)

	pgConn, err = gorm.Open(pg.Open(dsn), &gorm.Config{
		PrepareStmt: false,
		Logger:      customLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}
	if autoMigrate {
		if err := pgConn.AutoMigrate(pgTables...); err != nil {
			return nil, err
		}
	}

	db, err := pgConn.DB()
	if err != nil {
		return nil, err
	}
	db.SetMaxIdleConns(50)
	db.SetMaxOpenConns(200)
	db.SetConnMaxLifetime(time.Second * 600)
	db.SetConnMaxIdleTime(time.Minute * 5) // idle timeout

	return pgConn, nil
}

func CheckAndCreatedDB() error {
	if pgDSN == "" || pgDBName == "" {
		return ErrInvalidDSNOrDBName
	}
	dsn := strings.ReplaceAll(pgDSN, "dbname="+pgDBName, "")
	tx, err := gorm.Open(pg.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to open db: %w", err)
	}

	stmt := fmt.Sprintf("SELECT * FROM pg_database WHERE datname = '%s';", pgDBName)
	ret :=  make(map[string]interface{})
	if err := tx.Raw(stmt).Find(&ret).Error; err != nil {
		return err
	}
	if len(ret) <= 0 {
		log.Printf("Database not yet exists. Create '%v' database.", pgDBName)
		stmt := fmt.Sprintf("CREATE DATABASE %s;", pgDBName)
		if err := tx.Exec(stmt).Error; err != nil {
			return err
		}
	}
	// Try to close this connection.
	if db, err := tx.DB(); err == nil {
		db.Close()
	}
	dbCreated = true
	return nil
}

func Connect() (*gorm.DB, error) {
	pgLock.Lock()
	defer pgLock.Unlock()
	if pgConn == nil {
		if pgDSN == "" && !useEmulator {
			return nil, ErrInvalidDSNOrDBName
		}
		_, err := newConn(pgDSN)
		if err != nil {
			return nil, err
		}
	}
	return pgConn, nil
}

func AutoMigrate(dst ...interface{}) error {
	tx, err := Connect()
	if err != nil {
		return err
	}
	return tx.AutoMigrate(dst...)
}

func SetEmulator(isEmulator, verbose bool) {
	useEmulator = isEmulator
	verboseLogging = verbose
}
func SelectFirst(dest interface{}, conditions ...interface{}) error {
	if dest == nil {
		return errors.New("pg-select-first dest is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return fmt.Errorf("pg-select-first failed to connect to db: %w", err)
	}
	if err = db.First(dest, conditions...).Error; err != nil {
		return fmt.Errorf("pg-select-first get data failed: %w", err)
	}
	return nil
}
func SelectOne(dest interface{}, conditions ...interface{}) error {
	if dest == nil {
		return errors.New("pg-select-one dest is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return fmt.Errorf("pg-select-one failed to connect to db: %w", err)
	}
	if len(conditions) == 0 {
        return errors.New("pg-select-one: no conditions provided")
    }
	if err = db.Take(dest, conditions...).Error; err != nil {
		return fmt.Errorf("pg-select-one get data failed: %w", err)
	}
	return nil
}
func SelectLast(dest interface{}, conditions ...interface{}) error {
	if dest == nil {
		return errors.New("pg-select-last dest is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return fmt.Errorf("pg-select-last failed to connect to db: %w", err)
	}
	if err = db.Last(dest, conditions...).Error; err != nil {
		return fmt.Errorf("pg-select-last get data failed: %w", err)
	}
	return nil
}
func SelectAll(dest interface{}, conditions ...interface{}) error {
	if dest == nil {
		return errors.New("pg-select-all dest is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return fmt.Errorf("pg-select-all connect to db failed: %w", err)
	}
	if err = db.Find(dest, conditions...).Error; err != nil {
		return fmt.Errorf("pg-select-all find failed: %w", err)
	}
	return nil
}
func SelectByModel(model interface{}, dest interface{}, query interface{}, conditions ...interface{}) error {
	if dest == nil {
		return errors.New("pg-select-by-model dest is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return fmt.Errorf("pg-select-by-model connect to db failed %w", err)
	}
	if err = db.Model(model).Where(query, conditions...).Find(dest).Error; err != nil {
		return fmt.Errorf("pg-select-by-model find failed %w", err)
	}
	return nil
}
func SelectPage(limit, offset int, order interface{}, dest interface{}, conditions ...interface{}) error {
	if dest == nil {
		return errors.New("pg-select-page dest is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return fmt.Errorf("pg-select-page connect to db failed: %w", err)
	}

	tx := db.Limit(limit).Offset(offset).Order(order)
	tx.Find(dest, conditions...)
	if err = tx.Error; err != nil {
		return fmt.Errorf("pg-select-page find failed: %w", err)
	}
	return nil
}

// Delete returns no error if the record is not found.
func Delete(model interface{}, conditions ...interface{}) error {
	if model == nil {
		return errors.New("pg-delete model param is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return fmt.Errorf("pg-delete connect to db failed: %w", err)
	}
	err = db.Model(model).Delete(model, conditions...).Error
	if err == nil || errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	return fmt.Errorf("pg-delete delete data failed: %w", err)
}
func Updates(model interface{}, dest interface{}, query interface{}, conditions ...interface{}) error {
	if dest == nil || model == nil || query == nil {
		return errors.New("pg-updates param is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return fmt.Errorf("pg-updates connect to db failed: %w", err)
	}
	if err = db.Model(model).Where(query, conditions...).Updates(dest).Error; err != nil {
		return fmt.Errorf("pg-updates updates failed: %w", err)
	}
	return nil
}
func TableCount(dest interface{}, query interface{}, conditions ...interface{}) (int64, error) {
	if dest == nil {
		return 0, errors.New("pg-table-count dest is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return 0, fmt.Errorf("pg-table-count connect to db failed: %w", err)
	}
	var ret int64
	if err := db.Model(dest).Where(query, conditions...).Count(&ret).Error; err != nil {
		return 0, fmt.Errorf("pg-table-count count failed: %w", err)
	}
	return ret, nil
}
func TableCountByName(tableName string, query interface{}, conditions ...interface{}) (int64, error) {
	if tableName == "" {
		return 0, errors.New("pg-table-count-by-name table name is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return 0, fmt.Errorf("pg-table-count-by-name connect to db failed: %w", err)
	}
	var ret int64
	if err := db.Table(tableName).Where(query, conditions...).Count(&ret).Error; err != nil {
		return 0, fmt.Errorf("pg-table-count-by-name: count failed %w", err)
	}
	return ret, nil
}
func Update(model interface{}, column string, dest interface{}, query interface{}, conditions ...interface{}) error {
	if dest == nil || model == nil || query == nil {
		return errors.New("pg-update param is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return fmt.Errorf("pg-update connect to db failed: %w", err)
	}
	if err = db.Model(model).Where(query, conditions...).Update(column, dest).Error; err != nil {
		return fmt.Errorf("pg-update update data failed: %w", err)
	}
	return nil
}
func Create(data interface{}) error {
	if data == nil {
		return errors.New("pg-insert data is nil")
	}
	db, err := Connect()
	if err != nil || db == nil {
		return fmt.Errorf("pg-insert connect to db failed: %w", err)
	}
	if err = db.Create(data).Error; err != nil {
		return fmt.Errorf("pg-insert insert data failed: %w", err)
	}
	return nil
}

func newSqliteConn() *gorm.DB {
	dbFile := testDBFile
	_, err := os.Stat(dbFile)
	if err == nil {
		os.Remove(dbFile)
	}
	logLevel := logger.Silent
	if verboseLogging {
		logLevel = logger.Info
	}

	l := logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{
		SlowThreshold:             200 * time.Millisecond,
		LogLevel:                  logLevel,
		IgnoreRecordNotFoundError: false,
		Colorful:                  true,
	})
	sqliteConn, _ := gorm.Open(sqlite.Open(dbFile), &gorm.Config{
		Logger: l,
	})
	return sqliteConn
}

// Sort adds order conditions if requested.
// Call PGSort before calling PGPage so that it will be sorted before paged.
func Sort(p *gorm.DB, sortBy, sortDesc *string) *gorm.DB {
	if sortBy == nil || *sortBy == "" {
		return p
	}
	by := strings.Split(*sortBy, ",")
	desc := []string{}
	if sortDesc != nil && *sortDesc != "" {
		desc = strings.Split(*sortDesc, ",")
	}
	for i := 0; i < len(by); i++ {
		orderStr := by[i]
		if len(desc) > i && desc[i] == "desc" {
			orderStr += " desc"
		}
		p = p.Order(orderStr)
	}
	return p
}
func Page(p *gorm.DB, total int64, page, pageSize *int) *gorm.DB {
	if pageSize == nil || page == nil {
		return p
	}
	if *pageSize < 1 {
		*pageSize = 1
	}
	if *page < 1 {
		*page = 1
	}
	limit := *pageSize
	if limit > int(total) {
		limit = int(total)
	}
	offset := (*page - 1) * limit
	if offset < 0 {
		offset = 0
	}
	return p.Scopes(splitPage(limit, offset))
}
func splitPage(limit, offset int) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		return db.Limit(limit).Offset(offset)
	}
}
func RangeColumn(column string, min, max *int64) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		if min != nil && *min > 0 && max != nil && *max > 0 {
			return db.Where(column+" > ? and "+column+" < ?", min, max)
		} else if min != nil && *min > 0 {
			return db.Where(column+" > ?", min)
		} else if max != nil && *max > 0 {
			return db.Where(column+" < ?", max)
		} else {
			return db
		}
	}
}
