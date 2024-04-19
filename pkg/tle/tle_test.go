//
// Copyright 2021 The Sigstore Authors.
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

package tle

import (
	"encoding/base64"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	rekor_pb_common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekor_pb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	_ "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
)

func TestGenerateTransparencyLogEntry(t *testing.T) {
	type TestCase struct {
		description   string
		expectSuccess bool
		proposedEntry models.LogEntryAnon
		want          *rekor_pb.TransparencyLogEntry
	}

	b64Body := "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2MmQwOGYyOGM2OWNhZGE3YjQyYTQ1Nzk0YjQ3ZWU2YzgxYTdkZmE3MTY4NDZiMzljODhmMGFkMTljMjA2OTk3In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJQm14U0N1TW1HSzhNQWRMd1FWZ21TZjVXKzlkdU5iQXN1cUNQNlNucUxCUkFpRUFvNGtGRVdDTG9HcTVUaysrUEhtTEgrb3N1emVTRjN4OTdBbmVicTRlbVRvPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVUk1ha05EUVhKVFowRjNTVUpCWjBsVVRWQkRlVXdyYmxOb2MycHdaa2hZYUZkYVRVWkNUVUZIUlVSQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UVhFS1RWSlZkMFYzV1VSV1VWRkxSWGQ0ZW1GWFpIcGtSemw1V2xNMWExcFlXWGhGVkVGUVFtZE9Wa0pCVFZSRFNFNXdXak5PTUdJelNteE5RalJZUkZSSmVRcE5SRWwzVFdwRmQwNUVXWGhOVm05WVJGUkplVTFFU1hkTmFrVjNUbFJaZUUxR2IzZEZla1ZTVFVFNFIwRXhWVVZEYUUxSll6SnNibU16VW5aamJWVjNDbGRVUVZSQ1oyTnhhR3RxVDFCUlNVSkNaMmR4YUd0cVQxQlJUVUpDZDA1RFFVRlVVMVJ2VEhWS2N5OTFSV05IU2tRME5VWmFiVE5wWmxKTU4yOXVRVWNLWlZaNWJuWkhVbmN6WnpKMU0wbFhTREZuU2tSamNERjRSWFI2UVZCUWJYQmhlVGRtTmxCNE1XeFpNa0ZyWnpsMGEyb3dRa1J2UTNkdk5FbENlbXBEUXdwQlkyOTNSR2RaUkZaU01GQkJVVWd2UWtGUlJFRm5aVUZOUWsxSFFURlZaRXBSVVUxTlFXOUhRME56UjBGUlZVWkNkMDFFVFVGM1IwRXhWV1JGZDBWQ0NpOTNVVU5OUVVGM1NGRlpSRlpTTUU5Q1FsbEZSazlSYTNZNVoyMVpXVFpWU0doQ1pWSnJMMWx4VlVsaU1WRldiMDFDT0VkQk1WVmtTWGRSV1UxQ1lVRUtSa1pxUVVoc0sxSlNZVlp0Y1ZoeVRXdExSMVJKZEVGeGVHTllOazFIVFVkQk1WVmtSVkZTWTAxR2NVZFhSMmd3WkVoQ2VrOXBPSFphTW13d1lVaFdhUXBNYlU1MllsTTVjbGx1VGpCTU0xSnNZMjVLYUZwdE9YbGlVekZ5WkZkS2JHTXpVbWhaTW5OMlRHMWtjR1JIYURGWmFUa3pZak5LY2xwdGVIWmtNMDEyQ21KWFJuQmlhVFUxWWxkNFFXTnRWbTFqZVRsdldsZEdhMk41T1hSWldFNHdXbGhKZDBWbldVdExkMWxDUWtGSFJIWjZRVUpCWjFGRlkwaFdlbUZFUVcwS1FtZHZja0puUlVWQldVOHZUVUZGUmtKQ2FISlpiazR3VEROU2JHTnVTbWhhYlRsNVlsTXhjbVJYU214ak0xSm9XVEp6ZDA1bldVdExkMWxDUWtGSFJBcDJla0ZDUVhkUmIxcHFSVEZPVjFGNVdXMUplRTU2V210TlZFVTFXV3BHYlU5VVNUSk9WRlV6V1hwTk5WbDZTbWxQVkdzMVdtcFNhRnBxWjNkWmVrRTFDa0puYjNKQ1owVkZRVmxQTDAxQlJVSkNRM1J2WkVoU2QyTjZiM1pNTTFKMllUSldkVXh0Um1wa1IyeDJZbTVOZFZveWJEQmhTRlpwWkZoT2JHTnRUbllLWW01U2JHSnVVWFZaTWpsMFRVSTRSME5wYzBkQlVWRkNaemM0ZDBGUldVVkZXRXBzV201TmRtRkhWbWhhU0UxMllsZEdlbVJIVm5sTlEwRkhRMmx6UndwQlVWRkNaemM0ZDBGUlVVVkZhMG94WVZkNGEwbEdVbXhqTTFGblZVaFdhV0pIYkhwaFJFRkxRbWRuY1docmFrOVFVVkZFUVhkT2IwRkVRbXhCYWtWQkNtdDJORTFLYUdGRGFFMUJaMHBWVTNWWll6bFBWRWt3WTB0bU9XTnlObU14Y1RreVYyOXFMM1ZsV0RKRFR6Z3JMMDQyU25SM1FVNTRVSElyTjNWNlpGQUtRV3BDYVhwR2NHZEVMelJzWW5aa1NuRnplWE5HYlVSeU1TdFNNSGhKWjI1S1N5c3JaWGROYmtKaVMxQkVMemd3VTNJelFYTTVMMWxxV1U5M05EVjRkUXA2ZVdzOUNpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9fX19"
	bodyBytes, _ := base64.RawStdEncoding.DecodeString(b64Body)

	deadbeefBytes, _ := hex.DecodeString("deadbeef")
	abcdefaaBytes, _ := hex.DecodeString("abcdefaa")

	testCases := []TestCase{
		{
			description:   "valid entry",
			expectSuccess: true,
			proposedEntry: models.LogEntryAnon{
				Body:           swag.String("eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2MmQwOGYyOGM2OWNhZGE3YjQyYTQ1Nzk0YjQ3ZWU2YzgxYTdkZmE3MTY4NDZiMzljODhmMGFkMTljMjA2OTk3In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJQm14U0N1TW1HSzhNQWRMd1FWZ21TZjVXKzlkdU5iQXN1cUNQNlNucUxCUkFpRUFvNGtGRVdDTG9HcTVUaysrUEhtTEgrb3N1emVTRjN4OTdBbmVicTRlbVRvPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVUk1ha05EUVhKVFowRjNTVUpCWjBsVVRWQkRlVXdyYmxOb2MycHdaa2hZYUZkYVRVWkNUVUZIUlVSQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UVhFS1RWSlZkMFYzV1VSV1VWRkxSWGQ0ZW1GWFpIcGtSemw1V2xNMWExcFlXWGhGVkVGUVFtZE9Wa0pCVFZSRFNFNXdXak5PTUdJelNteE5RalJZUkZSSmVRcE5SRWwzVFdwRmQwNUVXWGhOVm05WVJGUkplVTFFU1hkTmFrVjNUbFJaZUUxR2IzZEZla1ZTVFVFNFIwRXhWVVZEYUUxSll6SnNibU16VW5aamJWVjNDbGRVUVZSQ1oyTnhhR3RxVDFCUlNVSkNaMmR4YUd0cVQxQlJUVUpDZDA1RFFVRlVVMVJ2VEhWS2N5OTFSV05IU2tRME5VWmFiVE5wWmxKTU4yOXVRVWNLWlZaNWJuWkhVbmN6WnpKMU0wbFhTREZuU2tSamNERjRSWFI2UVZCUWJYQmhlVGRtTmxCNE1XeFpNa0ZyWnpsMGEyb3dRa1J2UTNkdk5FbENlbXBEUXdwQlkyOTNSR2RaUkZaU01GQkJVVWd2UWtGUlJFRm5aVUZOUWsxSFFURlZaRXBSVVUxTlFXOUhRME56UjBGUlZVWkNkMDFFVFVGM1IwRXhWV1JGZDBWQ0NpOTNVVU5OUVVGM1NGRlpSRlpTTUU5Q1FsbEZSazlSYTNZNVoyMVpXVFpWU0doQ1pWSnJMMWx4VlVsaU1WRldiMDFDT0VkQk1WVmtTWGRSV1UxQ1lVRUtSa1pxUVVoc0sxSlNZVlp0Y1ZoeVRXdExSMVJKZEVGeGVHTllOazFIVFVkQk1WVmtSVkZTWTAxR2NVZFhSMmd3WkVoQ2VrOXBPSFphTW13d1lVaFdhUXBNYlU1MllsTTVjbGx1VGpCTU0xSnNZMjVLYUZwdE9YbGlVekZ5WkZkS2JHTXpVbWhaTW5OMlRHMWtjR1JIYURGWmFUa3pZak5LY2xwdGVIWmtNMDEyQ21KWFJuQmlhVFUxWWxkNFFXTnRWbTFqZVRsdldsZEdhMk41T1hSWldFNHdXbGhKZDBWbldVdExkMWxDUWtGSFJIWjZRVUpCWjFGRlkwaFdlbUZFUVcwS1FtZHZja0puUlVWQldVOHZUVUZGUmtKQ2FISlpiazR3VEROU2JHTnVTbWhhYlRsNVlsTXhjbVJYU214ak0xSm9XVEp6ZDA1bldVdExkMWxDUWtGSFJBcDJla0ZDUVhkUmIxcHFSVEZPVjFGNVdXMUplRTU2V210TlZFVTFXV3BHYlU5VVNUSk9WRlV6V1hwTk5WbDZTbWxQVkdzMVdtcFNhRnBxWjNkWmVrRTFDa0puYjNKQ1owVkZRVmxQTDAxQlJVSkNRM1J2WkVoU2QyTjZiM1pNTTFKMllUSldkVXh0Um1wa1IyeDJZbTVOZFZveWJEQmhTRlpwWkZoT2JHTnRUbllLWW01U2JHSnVVWFZaTWpsMFRVSTRSME5wYzBkQlVWRkNaemM0ZDBGUldVVkZXRXBzV201TmRtRkhWbWhhU0UxMllsZEdlbVJIVm5sTlEwRkhRMmx6UndwQlVWRkNaemM0ZDBGUlVVVkZhMG94WVZkNGEwbEdVbXhqTTFGblZVaFdhV0pIYkhwaFJFRkxRbWRuY1docmFrOVFVVkZFUVhkT2IwRkVRbXhCYWtWQkNtdDJORTFLYUdGRGFFMUJaMHBWVTNWWll6bFBWRWt3WTB0bU9XTnlObU14Y1RreVYyOXFMM1ZsV0RKRFR6Z3JMMDQyU25SM1FVNTRVSElyTjNWNlpGQUtRV3BDYVhwR2NHZEVMelJzWW5aa1NuRnplWE5HYlVSeU1TdFNNSGhKWjI1S1N5c3JaWGROYmtKaVMxQkVMemd3VTNJelFYTTVMMWxxV1U5M05EVjRkUXA2ZVdzOUNpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9fX19"),
				IntegratedTime: swag.Int64(123),
				LogID:          swag.String("deadbeef"),
				LogIndex:       swag.Int64(2),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						Checkpoint: swag.String("checkpoint"),
						Hashes:     []string{"deadbeef", "abcdefaa"},
						LogIndex:   swag.Int64(1),
						RootHash:   swag.String("abcdefaa"),
						TreeSize:   swag.Int64(2),
					},
					SignedEntryTimestamp: strfmt.Base64("set"),
				},
			},
			want: &rekor_pb.TransparencyLogEntry{
				LogIndex: 2,
				LogId: &rekor_pb_common.LogId{
					KeyId: deadbeefBytes,
				},
				KindVersion: &rekor_pb.KindVersion{
					Kind:    "hashedrekord",
					Version: "0.0.1",
				},
				IntegratedTime: 123,
				InclusionPromise: &rekor_pb.InclusionPromise{
					SignedEntryTimestamp: []byte("set"),
				},
				InclusionProof: &rekor_pb.InclusionProof{
					Checkpoint: &rekor_pb.Checkpoint{
						Envelope: "checkpoint",
					},
					Hashes:   [][]byte{deadbeefBytes, abcdefaaBytes},
					LogIndex: 1,
					RootHash: abcdefaaBytes,
					TreeSize: 2,
				},
				CanonicalizedBody: bodyBytes,
			},
		},
		{
			description:   "body is not valid base64",
			expectSuccess: false,
			proposedEntry: models.LogEntryAnon{
				Body:           swag.String("not_base_64"),
				IntegratedTime: swag.Int64(123),
				LogID:          swag.String("deadbeef"),
				LogIndex:       swag.Int64(1),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						Checkpoint: swag.String("checkpoint"),
						Hashes:     []string{"deadbeef", "abcdefaa"},
						LogIndex:   swag.Int64(1),
						RootHash:   swag.String("abcdefaa"),
						TreeSize:   swag.Int64(2),
					},
					SignedEntryTimestamp: strfmt.Base64("set"),
				},
			},
		},
		{
			description:   "logID is not valid hex",
			expectSuccess: false,
			proposedEntry: models.LogEntryAnon{
				Body:           swag.String("eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2MmQwOGYyOGM2OWNhZGE3YjQyYTQ1Nzk0YjQ3ZWU2YzgxYTdkZmE3MTY4NDZiMzljODhmMGFkMTljMjA2OTk3In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJQm14U0N1TW1HSzhNQWRMd1FWZ21TZjVXKzlkdU5iQXN1cUNQNlNucUxCUkFpRUFvNGtGRVdDTG9HcTVUaysrUEhtTEgrb3N1emVTRjN4OTdBbmVicTRlbVRvPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVUk1ha05EUVhKVFowRjNTVUpCWjBsVVRWQkRlVXdyYmxOb2MycHdaa2hZYUZkYVRVWkNUVUZIUlVSQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UVhFS1RWSlZkMFYzV1VSV1VWRkxSWGQ0ZW1GWFpIcGtSemw1V2xNMWExcFlXWGhGVkVGUVFtZE9Wa0pCVFZSRFNFNXdXak5PTUdJelNteE5RalJZUkZSSmVRcE5SRWwzVFdwRmQwNUVXWGhOVm05WVJGUkplVTFFU1hkTmFrVjNUbFJaZUUxR2IzZEZla1ZTVFVFNFIwRXhWVVZEYUUxSll6SnNibU16VW5aamJWVjNDbGRVUVZSQ1oyTnhhR3RxVDFCUlNVSkNaMmR4YUd0cVQxQlJUVUpDZDA1RFFVRlVVMVJ2VEhWS2N5OTFSV05IU2tRME5VWmFiVE5wWmxKTU4yOXVRVWNLWlZaNWJuWkhVbmN6WnpKMU0wbFhTREZuU2tSamNERjRSWFI2UVZCUWJYQmhlVGRtTmxCNE1XeFpNa0ZyWnpsMGEyb3dRa1J2UTNkdk5FbENlbXBEUXdwQlkyOTNSR2RaUkZaU01GQkJVVWd2UWtGUlJFRm5aVUZOUWsxSFFURlZaRXBSVVUxTlFXOUhRME56UjBGUlZVWkNkMDFFVFVGM1IwRXhWV1JGZDBWQ0NpOTNVVU5OUVVGM1NGRlpSRlpTTUU5Q1FsbEZSazlSYTNZNVoyMVpXVFpWU0doQ1pWSnJMMWx4VlVsaU1WRldiMDFDT0VkQk1WVmtTWGRSV1UxQ1lVRUtSa1pxUVVoc0sxSlNZVlp0Y1ZoeVRXdExSMVJKZEVGeGVHTllOazFIVFVkQk1WVmtSVkZTWTAxR2NVZFhSMmd3WkVoQ2VrOXBPSFphTW13d1lVaFdhUXBNYlU1MllsTTVjbGx1VGpCTU0xSnNZMjVLYUZwdE9YbGlVekZ5WkZkS2JHTXpVbWhaTW5OMlRHMWtjR1JIYURGWmFUa3pZak5LY2xwdGVIWmtNMDEyQ21KWFJuQmlhVFUxWWxkNFFXTnRWbTFqZVRsdldsZEdhMk41T1hSWldFNHdXbGhKZDBWbldVdExkMWxDUWtGSFJIWjZRVUpCWjFGRlkwaFdlbUZFUVcwS1FtZHZja0puUlVWQldVOHZUVUZGUmtKQ2FISlpiazR3VEROU2JHTnVTbWhhYlRsNVlsTXhjbVJYU214ak0xSm9XVEp6ZDA1bldVdExkMWxDUWtGSFJBcDJla0ZDUVhkUmIxcHFSVEZPVjFGNVdXMUplRTU2V210TlZFVTFXV3BHYlU5VVNUSk9WRlV6V1hwTk5WbDZTbWxQVkdzMVdtcFNhRnBxWjNkWmVrRTFDa0puYjNKQ1owVkZRVmxQTDAxQlJVSkNRM1J2WkVoU2QyTjZiM1pNTTFKMllUSldkVXh0Um1wa1IyeDJZbTVOZFZveWJEQmhTRlpwWkZoT2JHTnRUbllLWW01U2JHSnVVWFZaTWpsMFRVSTRSME5wYzBkQlVWRkNaemM0ZDBGUldVVkZXRXBzV201TmRtRkhWbWhhU0UxMllsZEdlbVJIVm5sTlEwRkhRMmx6UndwQlVWRkNaemM0ZDBGUlVVVkZhMG94WVZkNGEwbEdVbXhqTTFGblZVaFdhV0pIYkhwaFJFRkxRbWRuY1docmFrOVFVVkZFUVhkT2IwRkVRbXhCYWtWQkNtdDJORTFLYUdGRGFFMUJaMHBWVTNWWll6bFBWRWt3WTB0bU9XTnlObU14Y1RreVYyOXFMM1ZsV0RKRFR6Z3JMMDQyU25SM1FVNTRVSElyTjNWNlpGQUtRV3BDYVhwR2NHZEVMelJzWW5aa1NuRnplWE5HYlVSeU1TdFNNSGhKWjI1S1N5c3JaWGROYmtKaVMxQkVMemd3VTNJelFYTTVMMWxxV1U5M05EVjRkUXA2ZVdzOUNpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9fX19"),
				IntegratedTime: swag.Int64(123),
				LogID:          swag.String("not_valid_hex"),
				LogIndex:       swag.Int64(1),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						Checkpoint: swag.String("checkpoint"),
						Hashes:     []string{"deadbeef", "abcdefaa"},
						LogIndex:   swag.Int64(1),
						RootHash:   swag.String("abcdefaa"),
						TreeSize:   swag.Int64(2),
					},
					SignedEntryTimestamp: strfmt.Base64("set"),
				},
			},
		},
		{
			description:   "rootHash is not valid hex",
			expectSuccess: false,
			proposedEntry: models.LogEntryAnon{
				Body:           swag.String("eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2MmQwOGYyOGM2OWNhZGE3YjQyYTQ1Nzk0YjQ3ZWU2YzgxYTdkZmE3MTY4NDZiMzljODhmMGFkMTljMjA2OTk3In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJQm14U0N1TW1HSzhNQWRMd1FWZ21TZjVXKzlkdU5iQXN1cUNQNlNucUxCUkFpRUFvNGtGRVdDTG9HcTVUaysrUEhtTEgrb3N1emVTRjN4OTdBbmVicTRlbVRvPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVUk1ha05EUVhKVFowRjNTVUpCWjBsVVRWQkRlVXdyYmxOb2MycHdaa2hZYUZkYVRVWkNUVUZIUlVSQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UVhFS1RWSlZkMFYzV1VSV1VWRkxSWGQ0ZW1GWFpIcGtSemw1V2xNMWExcFlXWGhGVkVGUVFtZE9Wa0pCVFZSRFNFNXdXak5PTUdJelNteE5RalJZUkZSSmVRcE5SRWwzVFdwRmQwNUVXWGhOVm05WVJGUkplVTFFU1hkTmFrVjNUbFJaZUUxR2IzZEZla1ZTVFVFNFIwRXhWVVZEYUUxSll6SnNibU16VW5aamJWVjNDbGRVUVZSQ1oyTnhhR3RxVDFCUlNVSkNaMmR4YUd0cVQxQlJUVUpDZDA1RFFVRlVVMVJ2VEhWS2N5OTFSV05IU2tRME5VWmFiVE5wWmxKTU4yOXVRVWNLWlZaNWJuWkhVbmN6WnpKMU0wbFhTREZuU2tSamNERjRSWFI2UVZCUWJYQmhlVGRtTmxCNE1XeFpNa0ZyWnpsMGEyb3dRa1J2UTNkdk5FbENlbXBEUXdwQlkyOTNSR2RaUkZaU01GQkJVVWd2UWtGUlJFRm5aVUZOUWsxSFFURlZaRXBSVVUxTlFXOUhRME56UjBGUlZVWkNkMDFFVFVGM1IwRXhWV1JGZDBWQ0NpOTNVVU5OUVVGM1NGRlpSRlpTTUU5Q1FsbEZSazlSYTNZNVoyMVpXVFpWU0doQ1pWSnJMMWx4VlVsaU1WRldiMDFDT0VkQk1WVmtTWGRSV1UxQ1lVRUtSa1pxUVVoc0sxSlNZVlp0Y1ZoeVRXdExSMVJKZEVGeGVHTllOazFIVFVkQk1WVmtSVkZTWTAxR2NVZFhSMmd3WkVoQ2VrOXBPSFphTW13d1lVaFdhUXBNYlU1MllsTTVjbGx1VGpCTU0xSnNZMjVLYUZwdE9YbGlVekZ5WkZkS2JHTXpVbWhaTW5OMlRHMWtjR1JIYURGWmFUa3pZak5LY2xwdGVIWmtNMDEyQ21KWFJuQmlhVFUxWWxkNFFXTnRWbTFqZVRsdldsZEdhMk41T1hSWldFNHdXbGhKZDBWbldVdExkMWxDUWtGSFJIWjZRVUpCWjFGRlkwaFdlbUZFUVcwS1FtZHZja0puUlVWQldVOHZUVUZGUmtKQ2FISlpiazR3VEROU2JHTnVTbWhhYlRsNVlsTXhjbVJYU214ak0xSm9XVEp6ZDA1bldVdExkMWxDUWtGSFJBcDJla0ZDUVhkUmIxcHFSVEZPVjFGNVdXMUplRTU2V210TlZFVTFXV3BHYlU5VVNUSk9WRlV6V1hwTk5WbDZTbWxQVkdzMVdtcFNhRnBxWjNkWmVrRTFDa0puYjNKQ1owVkZRVmxQTDAxQlJVSkNRM1J2WkVoU2QyTjZiM1pNTTFKMllUSldkVXh0Um1wa1IyeDJZbTVOZFZveWJEQmhTRlpwWkZoT2JHTnRUbllLWW01U2JHSnVVWFZaTWpsMFRVSTRSME5wYzBkQlVWRkNaemM0ZDBGUldVVkZXRXBzV201TmRtRkhWbWhhU0UxMllsZEdlbVJIVm5sTlEwRkhRMmx6UndwQlVWRkNaemM0ZDBGUlVVVkZhMG94WVZkNGEwbEdVbXhqTTFGblZVaFdhV0pIYkhwaFJFRkxRbWRuY1docmFrOVFVVkZFUVhkT2IwRkVRbXhCYWtWQkNtdDJORTFLYUdGRGFFMUJaMHBWVTNWWll6bFBWRWt3WTB0bU9XTnlObU14Y1RreVYyOXFMM1ZsV0RKRFR6Z3JMMDQyU25SM1FVNTRVSElyTjNWNlpGQUtRV3BDYVhwR2NHZEVMelJzWW5aa1NuRnplWE5HYlVSeU1TdFNNSGhKWjI1S1N5c3JaWGROYmtKaVMxQkVMemd3VTNJelFYTTVMMWxxV1U5M05EVjRkUXA2ZVdzOUNpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9fX19"),
				IntegratedTime: swag.Int64(123),
				LogID:          swag.String("deadbeef"),
				LogIndex:       swag.Int64(1),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						Checkpoint: swag.String("checkpoint"),
						Hashes:     []string{"deadbeef", "abcdefaa"},
						LogIndex:   swag.Int64(1),
						RootHash:   swag.String("not_hex_string"),
						TreeSize:   swag.Int64(2),
					},
					SignedEntryTimestamp: strfmt.Base64("set"),
				},
			},
		},
		{
			description:   "one inclusion proof hash is not valid hex",
			expectSuccess: false,
			proposedEntry: models.LogEntryAnon{
				Body:           swag.String("eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2MmQwOGYyOGM2OWNhZGE3YjQyYTQ1Nzk0YjQ3ZWU2YzgxYTdkZmE3MTY4NDZiMzljODhmMGFkMTljMjA2OTk3In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FVUNJQm14U0N1TW1HSzhNQWRMd1FWZ21TZjVXKzlkdU5iQXN1cUNQNlNucUxCUkFpRUFvNGtGRVdDTG9HcTVUaysrUEhtTEgrb3N1emVTRjN4OTdBbmVicTRlbVRvPSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVUk1ha05EUVhKVFowRjNTVUpCWjBsVVRWQkRlVXdyYmxOb2MycHdaa2hZYUZkYVRVWkNUVUZIUlVSQlMwSm5aM0ZvYTJwUFVGRlJSRUY2UVhFS1RWSlZkMFYzV1VSV1VWRkxSWGQ0ZW1GWFpIcGtSemw1V2xNMWExcFlXWGhGVkVGUVFtZE9Wa0pCVFZSRFNFNXdXak5PTUdJelNteE5RalJZUkZSSmVRcE5SRWwzVFdwRmQwNUVXWGhOVm05WVJGUkplVTFFU1hkTmFrVjNUbFJaZUUxR2IzZEZla1ZTVFVFNFIwRXhWVVZEYUUxSll6SnNibU16VW5aamJWVjNDbGRVUVZSQ1oyTnhhR3RxVDFCUlNVSkNaMmR4YUd0cVQxQlJUVUpDZDA1RFFVRlVVMVJ2VEhWS2N5OTFSV05IU2tRME5VWmFiVE5wWmxKTU4yOXVRVWNLWlZaNWJuWkhVbmN6WnpKMU0wbFhTREZuU2tSamNERjRSWFI2UVZCUWJYQmhlVGRtTmxCNE1XeFpNa0ZyWnpsMGEyb3dRa1J2UTNkdk5FbENlbXBEUXdwQlkyOTNSR2RaUkZaU01GQkJVVWd2UWtGUlJFRm5aVUZOUWsxSFFURlZaRXBSVVUxTlFXOUhRME56UjBGUlZVWkNkMDFFVFVGM1IwRXhWV1JGZDBWQ0NpOTNVVU5OUVVGM1NGRlpSRlpTTUU5Q1FsbEZSazlSYTNZNVoyMVpXVFpWU0doQ1pWSnJMMWx4VlVsaU1WRldiMDFDT0VkQk1WVmtTWGRSV1UxQ1lVRUtSa1pxUVVoc0sxSlNZVlp0Y1ZoeVRXdExSMVJKZEVGeGVHTllOazFIVFVkQk1WVmtSVkZTWTAxR2NVZFhSMmd3WkVoQ2VrOXBPSFphTW13d1lVaFdhUXBNYlU1MllsTTVjbGx1VGpCTU0xSnNZMjVLYUZwdE9YbGlVekZ5WkZkS2JHTXpVbWhaTW5OMlRHMWtjR1JIYURGWmFUa3pZak5LY2xwdGVIWmtNMDEyQ21KWFJuQmlhVFUxWWxkNFFXTnRWbTFqZVRsdldsZEdhMk41T1hSWldFNHdXbGhKZDBWbldVdExkMWxDUWtGSFJIWjZRVUpCWjFGRlkwaFdlbUZFUVcwS1FtZHZja0puUlVWQldVOHZUVUZGUmtKQ2FISlpiazR3VEROU2JHTnVTbWhhYlRsNVlsTXhjbVJYU214ak0xSm9XVEp6ZDA1bldVdExkMWxDUWtGSFJBcDJla0ZDUVhkUmIxcHFSVEZPVjFGNVdXMUplRTU2V210TlZFVTFXV3BHYlU5VVNUSk9WRlV6V1hwTk5WbDZTbWxQVkdzMVdtcFNhRnBxWjNkWmVrRTFDa0puYjNKQ1owVkZRVmxQTDAxQlJVSkNRM1J2WkVoU2QyTjZiM1pNTTFKMllUSldkVXh0Um1wa1IyeDJZbTVOZFZveWJEQmhTRlpwWkZoT2JHTnRUbllLWW01U2JHSnVVWFZaTWpsMFRVSTRSME5wYzBkQlVWRkNaemM0ZDBGUldVVkZXRXBzV201TmRtRkhWbWhhU0UxMllsZEdlbVJIVm5sTlEwRkhRMmx6UndwQlVWRkNaemM0ZDBGUlVVVkZhMG94WVZkNGEwbEdVbXhqTTFGblZVaFdhV0pIYkhwaFJFRkxRbWRuY1docmFrOVFVVkZFUVhkT2IwRkVRbXhCYWtWQkNtdDJORTFLYUdGRGFFMUJaMHBWVTNWWll6bFBWRWt3WTB0bU9XTnlObU14Y1RreVYyOXFMM1ZsV0RKRFR6Z3JMMDQyU25SM1FVNTRVSElyTjNWNlpGQUtRV3BDYVhwR2NHZEVMelJzWW5aa1NuRnplWE5HYlVSeU1TdFNNSGhKWjI1S1N5c3JaWGROYmtKaVMxQkVMemd3VTNJelFYTTVMMWxxV1U5M05EVjRkUXA2ZVdzOUNpMHRMUzB0UlU1RUlFTkZVbFJKUmtsRFFWUkZMUzB0TFMwSyJ9fX19"),
				IntegratedTime: swag.Int64(123),
				LogID:          swag.String("deadbeef"),
				LogIndex:       swag.Int64(1),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						Checkpoint: swag.String("checkpoint"),
						Hashes:     []string{"invalid_hex", "abcdefaa"},
						LogIndex:   swag.Int64(1),
						RootHash:   swag.String("abcdefaa"),
						TreeSize:   swag.Int64(2),
					},
					SignedEntryTimestamp: strfmt.Base64("set"),
				},
			},
		},
		{
			description:   "body is valid base64 but not valid entry",
			expectSuccess: false,
			proposedEntry: models.LogEntryAnon{
				Body:           swag.String("aW52YWxpZF9lbnRyeQo=", // "invalid_entry)"
				IntegratedTime: swag.Int64(123),
				LogID:          swag.String("deadbeef"),
				LogIndex:       swag.Int64(1),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						Checkpoint: swag.String("checkpoint"),
						Hashes:     []string{"deadbeef", "abcdefaa"},
						LogIndex:   swag.Int64(1),
						RootHash:   swag.String("abcdefaa"),
						TreeSize:   swag.Int64(2),
					},
					SignedEntryTimestamp: strfmt.Base64("set"),
				},
			},
		},
		{
			description:   "kind/version are valid but spec is not schema valid",
			expectSuccess: false,
			proposedEntry: models.LogEntryAnon{
				Body:           swag.String("eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7ImhhcyI6eyJhbGdvcml0aG0iOiJzaGEyNTYiLCJ2YWx1ZSI6IjYyZDA4ZjI4YzY5Y2FkYTdiNDJhNDU3OTRiNDdlZTZjODFhN2RmYTcxNjg0NmIzOWM4OGYwYWQxOWMyMDY5OTcifX0sInNpZ25hdHVyZSI6eyJjb250ZW50IjoiTUVVQ0lCbXhTQ3VNbUdLOE1BZEx3UVZnbVNmNVcrOWR1TmJBc3VxQ1A2U25xTEJSQWlFQW80a0ZFV0NMb0dxNVRrKytQSG1MSCtvc3V6ZVNGM3g5N0FuZWJxNGVtVG89IiwicHVibGljS2V5Ijp7ImNvbnRlbnQiOiJMUzB0TFMxQ1JVZEpUaUJEUlZKVVNVWkpRMEZVUlMwdExTMHRDazFKU1VSTWFrTkRRWEpUWjBGM1NVSkJaMGxVVFZCRGVVd3JibE5vYzJwd1praFlhRmRhVFVaQ1RVRkhSVVJCUzBKblozRm9hMnBQVUZGUlJFRjZRWEVLVFZKVmQwVjNXVVJXVVZGTFJYZDRlbUZYWkhwa1J6bDVXbE0xYTFwWVdYaEZWRUZRUW1kT1ZrSkJUVlJEU0U1d1dqTk9NR0l6U214TlFqUllSRlJKZVFwTlJFbDNUV3BGZDA1RVdYaE5WbTlZUkZSSmVVMUVTWGROYWtWM1RsUlplRTFHYjNkRmVrVlNUVUU0UjBFeFZVVkRhRTFKWXpKc2JtTXpVblpqYlZWM0NsZFVRVlJDWjJOeGFHdHFUMUJSU1VKQ1oyZHhhR3RxVDFCUlRVSkNkMDVEUVVGVVUxUnZUSFZLY3k5MVJXTkhTa1EwTlVaYWJUTnBabEpNTjI5dVFVY0taVlo1Ym5aSFVuY3paekoxTTBsWFNERm5Ta1JqY0RGNFJYUjZRVkJRYlhCaGVUZG1ObEI0TVd4Wk1rRnJaemwwYTJvd1FrUnZRM2R2TkVsQ2VtcERRd3BCWTI5M1JHZFpSRlpTTUZCQlVVZ3ZRa0ZSUkVGblpVRk5RazFIUVRGVlpFcFJVVTFOUVc5SFEwTnpSMEZSVlVaQ2QwMUVUVUYzUjBFeFZXUkZkMFZDQ2k5M1VVTk5RVUYzU0ZGWlJGWlNNRTlDUWxsRlJrOVJhM1k1WjIxWldUWlZTR2hDWlZKckwxbHhWVWxpTVZGV2IwMUNPRWRCTVZWa1NYZFJXVTFDWVVFS1JrWnFRVWhzSzFKU1lWWnRjVmh5VFd0TFIxUkpkRUZ4ZUdOWU5rMUhUVWRCTVZWa1JWRlNZMDFHY1VkWFIyZ3daRWhDZWs5cE9IWmFNbXd3WVVoV2FRcE1iVTUyWWxNNWNsbHVUakJNTTFKc1kyNUthRnB0T1hsaVV6RnlaRmRLYkdNelVtaFpNbk4yVEcxa2NHUkhhREZaYVRrellqTktjbHB0ZUhaa00wMTJDbUpYUm5CaWFUVTFZbGQ0UVdOdFZtMWplVGx2V2xkR2EyTjVPWFJaV0U0d1dsaEpkMFZuV1V0TGQxbENRa0ZIUkhaNlFVSkJaMUZGWTBoV2VtRkVRVzBLUW1kdmNrSm5SVVZCV1U4dlRVRkZSa0pDYUhKWmJrNHdURE5TYkdOdVNtaGFiVGw1WWxNeGNtUlhTbXhqTTFKb1dUSnpkMDVuV1V0TGQxbENRa0ZIUkFwMmVrRkNRWGRSYjFwcVJURk9WMUY1V1cxSmVFNTZXbXROVkVVMVdXcEdiVTlVU1RKT1ZGVXpXWHBOTlZsNlNtbFBWR3MxV21wU2FGcHFaM2RaZWtFMUNrSm5iM0pDWjBWRlFWbFBMMDFCUlVKQ1EzUnZaRWhTZDJONmIzWk1NMUoyWVRKV2RVeHRSbXBrUjJ4MlltNU5kVm95YkRCaFNGWnBaRmhPYkdOdFRuWUtZbTVTYkdKdVVYVlpNamwwVFVJNFIwTnBjMGRCVVZGQ1p6YzRkMEZSV1VWRldFcHNXbTVOZG1GSFZtaGFTRTEyWWxkR2VtUkhWbmxOUTBGSFEybHpSd3BCVVZGQ1p6YzRkMEZSVVVWRmEwb3hZVmQ0YTBsR1VteGpNMUZuVlVoV2FXSkhiSHBoUkVGTFFtZG5jV2hyYWs5UVVWRkVRWGRPYjBGRVFteEJha1ZCQ210Mk5FMUthR0ZEYUUxQlowcFZVM1ZaWXpsUFZFa3dZMHRtT1dOeU5tTXhjVGt5VjI5cUwzVmxXREpEVHpnckwwNDJTblIzUVU1NFVISXJOM1Y2WkZBS1FXcENhWHBHY0dkRUx6UnNZblprU25GemVYTkdiVVJ5TVN0U01IaEpaMjVLU3lzclpYZE5ia0ppUzFCRUx6Z3dVM0l6UVhNNUwxbHFXVTkzTkRWNGRRcDZlV3M5Q2kwdExTMHRSVTVFSUVORlVsUkpSa2xEUVZSRkxTMHRMUzBLIn19fX0K"),
				IntegratedTime: swag.Int64(123),
				LogID:          swag.String("deadbeef"),
				LogIndex:       swag.Int64(1),
				Verification: &models.LogEntryAnonVerification{
					InclusionProof: &models.InclusionProof{
						Checkpoint: swag.String("checkpoint"),
						Hashes:     []string{"deadbeef", "abcdefaa"},
						LogIndex:   swag.Int64(1),
						RootHash:   swag.String("abcdefaa"),
						TreeSize:   swag.Int64(2),
					},
					SignedEntryTimestamp: strfmt.Base64("set"),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			e, err := GenerateTransparencyLogEntry(tc.proposedEntry)
			if (err == nil) != tc.expectSuccess {
				t.Fatalf("unexpected result: %v", err)
			}

			if tc.expectSuccess && !reflect.DeepEqual(e, tc.want) {
				t.Errorf("unexpected value returned; got %v, wanted %v", e, tc.want)
			}
		})
	}
}
