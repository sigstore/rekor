package _package

import (
	"context"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/log"
	"github.com/sigstore/rekor/pkg/types"
	pkg "github.com/sigstore/rekor/pkg/types/package"
)

const APIVERSION = "0.0.1"

func init() {
	if err := pkg.VersionMap.SetEntryFactory(APIVERSION, NewEntry); err != nil {
		log.Logger.Panic(err)
	}
}

type V001Entry struct {
	PackageModel models.PackageV001Schema
}

func NewEntry() types.EntryImpl {
	return &V001Entry{}
}

func (v V001Entry) APIVersion() string {
	// TODO implement me
	panic("implement me")
}

func (v V001Entry) IndexKeys() ([]string, error) {
	// TODO implement me
	panic("implement me")
}

func (v V001Entry) Canonicalize(ctx context.Context) ([]byte, error) {
	// TODO implement me
	panic("implement me")
}

func (v V001Entry) Unmarshal(e models.ProposedEntry) error {
	// TODO implement me
	panic("implement me")
}

func (v V001Entry) Attestation() []byte {
	// TODO implement me
	panic("implement me")
}

func (v V001Entry) CreateFromArtifactProperties(ctx context.Context, properties types.ArtifactProperties) (models.ProposedEntry, error) {
	// TODO implement me
	panic("implement me")
}
