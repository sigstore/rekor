// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mysql

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jmoiron/sqlx"

	"go.uber.org/goleak"
)

func TestLookupIndices(t *testing.T) {
	keys := []string{"87c1b129fbadd7b6e9abc0a9ef7695436d767aece042bec198a97e949fcbe14c"}
	value := []string{"1e1f2c881ae0608ec77ebf88a75c66d3099113a7343238f2f7a0ebb91a4ed335"}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("unexpected error creating mock db: %v", err)
	}

	isp := IndexStorageProvider{sqlx.NewDb(db, "mysql")}
	defer isp.Shutdown()

	mock.ExpectQuery(lookupStmt).WithArgs(keys[0]).WillReturnRows(sqlmock.NewRows(value))

	_, err = isp.LookupIndices(context.Background(), keys)
	if err != nil {
		t.Error(err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	expectedErr := errors.New("badness")
	mock.ExpectQuery(lookupStmt).WillReturnError(expectedErr)
	if _, err := isp.LookupIndices(context.Background(), keys); err == nil {
		t.Error("unexpected success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestWriteIndex(t *testing.T) {
	keys := []string{"87c1b129fbadd7b6e9abc0a9ef7695436d767aece042bec198a97e949fcbe14c"}
	value := "1e1f2c881ae0608ec77ebf88a75c66d3099113a7343238f2f7a0ebb91a4ed335"
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatalf("unexpected error creating mock db: %v", err)
	}

	re := regexp.MustCompile(`:[a-z]*`)
	expectedStmt := string(re.ReplaceAll([]byte(writeStmt), []byte("?")))

	isp := IndexStorageProvider{sqlx.NewDb(db, "mysql")}
	defer isp.Shutdown()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations not met: %v", err)
	}

	mock.ExpectExec(expectedStmt).WithArgs(keys[0], value).WillReturnResult(sqlmock.NewResult(1, 1))
	if err := isp.WriteIndex(context.Background(), keys, value); err != nil {
		t.Errorf("%v, %v", expectedStmt, err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}

	expectedErr := errors.New("badness")
	mock.ExpectExec(expectedStmt).WillReturnError(expectedErr)
	if err := isp.WriteIndex(context.Background(), keys, value); err == nil {
		t.Error("unexpected success")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

func TestUninitializedClient(t *testing.T) {
	// this is not initialized with a real mysql client
	isp := IndexStorageProvider{}
	if _, err := isp.LookupIndices(context.Background(), []string{"key"}); err == nil {
		t.Error("unexpected success")
	}
	if err := isp.WriteIndex(context.Background(), []string{"key"}, "value"); err == nil {
		t.Error("unexpected success")
	}
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
