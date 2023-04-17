package osv

import (
	"reflect"
	"testing"

	cyclone "github.com/CycloneDX/cyclonedx-go"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	provider := Provider{}
	info := provider.Info()
	assert.Equal(t, "OSV Vulnerability Database (https://osv.dev)", info)
}

func TestProvider_Scan(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", osvURL,
		httpmock.NewBytesResponder(200, osvTestResponse()))

	provider := Provider{}
	packages, err := provider.Scan([]string{"pkg:golang/github.com/briandowns/spinner@v1.19.0"}, nil)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:golang/github.com/briandowns/spinner@v1.19.0", packages[0].Purl)
	assert.Len(t, packages[0].Vulnerabilities, 1)
	httpmock.GetTotalCallCount()
}

func TestProvider_BadResponse(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", osvURL,
		httpmock.NewBytesResponder(500, []byte{}))

	provider := Provider{}
	_, err := provider.Scan([]string{"pkg:golang/github.com/briandowns/spinner@v1.19.0"}, nil)
	assert.Error(t, err)
	assert.Equal(t, "error retrieving vulnerability data (500)", err.Error())
}

func osvTestResponse() []byte {
	response := `
	{
		"vulns": [{
				"id": "GHSA-462w-v97r-4m45",
				"summary": "High severity vulnerability that affects Jinja2",
				"details": "In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape.",
				"aliases": [
					"CVE-2019-10906"
				],
				"modified": "2022-08-15T08:49:16.398254Z",
				"published": "2019-04-10T14:30:24Z",
				"database_specific": {
					"cwe_ids": [],
					"severity": "HIGH",
					"github_reviewed": true
				},
				"references": [{
						"type": "ADVISORY",
						"url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10906"
					},
					{
						"type": "WEB",
						"url": "https://access.redhat.com/errata/RHSA-2019:1152"
					},
					{
						"type": "WEB",
						"url": "https://access.redhat.com/errata/RHSA-2019:1237"
					},
					{
						"type": "WEB",
						"url": "https://access.redhat.com/errata/RHSA-2019:1329"
					},
					{
						"type": "ADVISORY",
						"url": "https://github.com/advisories/GHSA-462w-v97r-4m45"
					},
					{
						"type": "WEB",
						"url": "https://lists.apache.org/thread.html/09fc842ff444cd43d9d4c510756fec625ef8eb1175f14fd21de2605f@%3Cdevnull.infra.apache.org%3E"
					},
					{
						"type": "WEB",
						"url": "https://lists.apache.org/thread.html/2b52b9c8b9d6366a4f1b407a8bde6af28d9fc73fdb3b37695fd0d9ac@%3Cdevnull.infra.apache.org%3E"
					},
					{
						"type": "WEB",
						"url": "https://lists.apache.org/thread.html/320441dccbd9a545320f5f07306d711d4bbd31ba43dc9eebcfc602df@%3Cdevnull.infra.apache.org%3E"
					},
					{
						"type": "WEB",
						"url": "https://lists.apache.org/thread.html/46c055e173b52d599c648a98199972dbd6a89d2b4c4647b0500f2284@%3Cdevnull.infra.apache.org%3E"
					},
					{
						"type": "WEB",
						"url": "https://lists.apache.org/thread.html/57673a78c4d5c870d3f21465c7e2946b9f8285c7c57e54c2ae552f02@%3Ccommits.airflow.apache.org%3E"
					},
					{
						"type": "WEB",
						"url": "https://lists.apache.org/thread.html/7f39f01392d320dfb48e4901db68daeece62fd60ef20955966739993@%3Ccommits.airflow.apache.org%3E"
					},
					{
						"type": "WEB",
						"url": "https://lists.apache.org/thread.html/b2380d147b508bbcb90d2cad443c159e63e12555966ab4f320ee22da@%3Ccommits.airflow.apache.org%3E"
					},
					{
						"type": "WEB",
						"url": "https://lists.apache.org/thread.html/f0c4a03418bcfe70c539c5dbaf99c04c98da13bfa1d3266f08564316@%3Ccommits.airflow.apache.org%3E"
					},
					{
						"type": "WEB",
						"url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DSW3QZMFVVR7YE3UT4YRQA272TYAL5AF/"
					},
					{
						"type": "WEB",
						"url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QCDYIS254EJMBNWOG4S5QY6AOTOR4TZU/"
					},
					{
						"type": "WEB",
						"url": "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TS7IVZAJBWOHNRDMFJDIZVFCMRP6YIUQ/"
					},
					{
						"type": "WEB",
						"url": "https://palletsprojects.com/blog/jinja-2-10-1-released"
					},
					{
						"type": "WEB",
						"url": "https://usn.ubuntu.com/4011-1/"
					},
					{
						"type": "WEB",
						"url": "https://usn.ubuntu.com/4011-2/"
					},
					{
						"type": "WEB",
						"url": "http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00030.html"
					},
					{
						"type": "WEB",
						"url": "http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00064.html"
					}
				],
				"affected": [{
					"package": {
						"name": "jinja2",
						"ecosystem": "PyPI",
						"purl": "pkg:pypi/jinja2"
					},
					"ranges": [{
						"type": "ECOSYSTEM",
						"events": [{
								"introduced": "0"
							},
							{
								"fixed": "2.10.1"
							}
						]
					}],
					"versions": [
						"2.0",
						"2.0rc1",
						"2.1",
						"2.1.1",
						"2.10",
						"2.2",
						"2.2.1",
						"2.3",
						"2.3.1",
						"2.4",
						"2.4.1",
						"2.5",
						"2.5.1",
						"2.5.2",
						"2.5.3",
						"2.5.4",
						"2.5.5",
						"2.6",
						"2.7",
						"2.7.1",
						"2.7.2",
						"2.7.3",
						"2.8",
						"2.8.1",
						"2.9",
						"2.9.1",
						"2.9.2",
						"2.9.3",
						"2.9.4",
						"2.9.5",
						"2.9.6"
					],
					"database_specific": {
						"source": "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2019/04/GHSA-462w-v97r-4m45/GHSA-462w-v97r-4m45.json"
					}
				}],
				"schema_version": "1.2.0",
				"severity": [{
					"type": "CVSS_V3",
					"score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
				}]
			}
	
		]
	}`
	return []byte(response)
}

func TestToVDR(t *testing.T) {
	type args struct {
		vulns []Vuln
	}
	tests := []struct {
		name    string
		args    args
		wantVdr *cyclone.BOM
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotVdr := ToVDR(tt.args.vulns); !reflect.DeepEqual(gotVdr, tt.wantVdr) {
				t.Errorf("ToVDR() = %v, want %v", gotVdr, tt.wantVdr)
			}
		})
	}
}
