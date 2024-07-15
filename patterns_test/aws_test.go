// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package patterns_test

import (
	"testing"

	"github.com/elastic/go-grok"
	"github.com/elastic/go-grok/patterns"
	"github.com/stretchr/testify/require"
)

func TestParseWithPatterns_AWS(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"S3 request",
			"%{S3_REQUEST_LINE}",
			"GET https://127.0.0.1 HTTP/1.1",
			map[string]string{
				"http.request.method": "GET",
				"url.original":        "https://127.0.0.1",
				"http.version":        "1.1",
			},
		},

		{
			"ELB URIHOST",
			"%{ELB_URIHOST}",
			"example.com:80",
			map[string]string{
				"url.domain": "example.com",
				"url.port":   "80",
			},
		},

		{
			"ELB URIPATHQUERY",
			"%{ELB_URIPATHQUERY}",
			"/path/to/resource?query=param",
			map[string]string{
				"url.path":  "/path/to/resource",
				"url.query": "query=param",
			},
		},

		{
			"ELB URIPATHPARAM",
			"%{ELB_URIPATHPARAM}",
			"/path/to/resource?query=param",
			map[string]string{
				"url.path":  "/path/to/resource",
				"url.query": "query=param",
			},
		},

		{
			"ELB URI",
			"%{ELB_URI}",
			"https://username:password@example.com:80/path/to/resource?query=param",
			map[string]string{
				"url.scheme":   "https",
				"url.username": "username",
				"url.domain":   "example.com",
				"url.port":     "80",
				"url.path":     "/path/to/resource",
				"url.query":    "query=param",
			},
		},

		{
			"ELB REQUEST LINE",
			"%{ELB_REQUEST_LINE}",
			"GET https://username:password@example.com:80/path/to/resource?query=param HTTP/1.1",
			map[string]string{
				"http.request.method": "GET",
				"url.original":        "https://username:password@example.com:80/path/to/resource?query=param",
				"http.version":        "1.1",

				"url.scheme":   "https",
				"url.username": "username",
				"url.domain":   "example.com",
				"url.port":     "80",
				"url.path":     "/path/to/resource",
				"url.query":    "query=param",
			},
		},

		{
			"ELB V1 HTTP LOG",
			"%{ELB_V1_HTTP_LOG}",
			"2024-06-18T12:34:56.789Z my-elb 192.168.1.1:12345 10.0.0.1:80 0.001 0.002 0.003 200 500 1234 5678 \"GET https://username:password@example.com:80/path/to/resource?query=param HTTP/1.1\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\" TLS_AES_256_GCM_SHA384 TLSv1.2",
			map[string]string{
				"timestamp":                                 "2024-06-18T12:34:56.789Z",
				"aws.elb.name":                              "my-elb",
				"source.address":                            "192.168.1.1",
				"source.port":                               "12345",
				"aws.elb.backend.ip":                        "10.0.0.1",
				"aws.elb.backend.port":                      "80",
				"aws.elb.request_processing_time.sec":       "0.001",
				"aws.elb.backend_processing_time.sec":       "0.002",
				"aws.elb.response_processing_time.sec":      "0.003",
				"http.response.status_code":                 "200",
				"aws.elb.backend.http.response.status_code": "500",
				"http.request.body.size":                    "1234",
				"http.response.body.size":                   "5678",
				"http.request.method":                       "GET",
				"url.scheme":                                "https",
				"url.username":                              "username",
				"url.domain":                                "example.com",
				"url.port":                                  "80",
				"url.path":                                  "/path/to/resource",
				"url.query":                                 "query=param",
				"url.original":                              "https://username:password@example.com:80/path/to/resource?query=param",
				"http.version":                              "1.1",
				"user_agent.original":                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
				"tls.cipher":                                "TLS_AES_256_GCM_SHA384",
				"aws.elb.ssl_protocol":                      "TLSv1.2",
			},
		},

		{
			"ELB ACCESS LOG",
			"%{ELB_ACCESS_LOG}",
			"2024-06-18T12:34:56.789Z my-elb 192.168.1.1:12345 10.0.0.1:80 0.001 0.002 0.003 200 500 1234 5678 \"GET https://username:password@example.com:80/path/to/resource?query=param HTTP/1.1\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\" TLS_AES_256_GCM_SHA384 TLSv1.2",
			map[string]string{
				"timestamp":                                 "2024-06-18T12:34:56.789Z",
				"aws.elb.name":                              "my-elb",
				"source.address":                            "192.168.1.1",
				"source.port":                               "12345",
				"aws.elb.backend.ip":                        "10.0.0.1",
				"aws.elb.backend.port":                      "80",
				"aws.elb.request_processing_time.sec":       "0.001",
				"aws.elb.backend_processing_time.sec":       "0.002",
				"aws.elb.response_processing_time.sec":      "0.003",
				"http.response.status_code":                 "200",
				"aws.elb.backend.http.response.status_code": "500",
				"http.request.body.size":                    "1234",
				"http.response.body.size":                   "5678",
				"http.request.method":                       "GET",
				"url.scheme":                                "https",
				"url.username":                              "username",
				"url.domain":                                "example.com",
				"url.port":                                  "80",
				"url.path":                                  "/path/to/resource",
				"url.query":                                 "query=param",
				"url.original":                              "https://username:password@example.com:80/path/to/resource?query=param",
				"http.version":                              "1.1",
				"user_agent.original":                       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
				"tls.cipher":                                "TLS_AES_256_GCM_SHA384",
				"aws.elb.ssl_protocol":                      "TLSv1.2",
			},
		},
		{
			"CLOUDFRONT ACCESS LOG",
			"%{CLOUDFRONT_ACCESS_LOG}",
			"2024-06-18\t12:34:56\tLAX1\t12345\t192.168.1.1\tGET\texample.com\t/path/to/resource\t200\thttp://referrer.com\tMozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\tquery=param\tcookie=example\tHit\t1234567890\tcloudfront.example.com\thttps\t67890\t0.123\t203.0.113.1\tTLSv1.2\tTLS_AES_256_GCM_SHA384\tHit\tHTTP/1.1\tMiss\t0\t1234\t5678\t91011\ttext/html\t1234\t5678\t91011",
			map[string]string{
				"timestamp":                                  "2024-06-18\t12:34:56",
				"aws.cloudfront.x_edge_location":             "LAX1",
				"destination.bytes":                          "12345",
				"source.address":                             "192.168.1.1",
				"http.request.method":                        "GET",
				"url.domain":                                 "example.com",
				"url.path":                                   "/path/to/resource",
				"http.response.status_code":                  "200",
				"http.request.referrer":                      "http://referrer.com",
				"user_agent.original":                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
				"url.query":                                  "query=param",
				"aws.cloudfront.http.request.cookie":         "cookie=example",
				"aws.cloudfront.x_edge_result_type":          "Hit",
				"aws.cloudfront.x_edge_request_id":           "1234567890",
				"aws.cloudfront.http.request.host":           "cloudfront.example.com",
				"network.protocol.name":                      "https",
				"source.bytes":                               "67890",
				"aws.cloudfront.time_taken":                  "0.123",
				"network.forwarded_ip":                       "203.0.113.1",
				"aws.cloudfront.ssl_protocol":                "TLSv1.2",
				"tls.cipher":                                 "TLS_AES_256_GCM_SHA384",
				"aws.cloudfront.x_edge_response_result_type": "Hit",
				"http.version":                               "1.1",
				"aws.cloudfront.fle_status":                  "Miss",
				"aws.cloudfront.fle_encrypted_fields":        "0",
				"source.port":                                "1234",
				"aws.cloudfront.time_to_first_byte":          "5678",
				"aws.cloudfront.x_edge_detailed_result_type": "91011",
				"http.request.mime_type":                     "text/html",
				"aws.cloudfront.http.request.size":           "1234",
				"aws.cloudfront.http.request.range.start":    "5678",
				"aws.cloudfront.http.request.range.end":      "91011",
			},
		},

		{
			"S3 ACCESS LOG",
			"%{S3_ACCESS_LOG}",
			"bucketOwner myBucket [18/Jun/2024:12:34:56 +0000] 192.168.1.1 user12345 requestID12345 REST.GET.OBJECT objectKey \"GET https://127.0.0.1 HTTP/1.1\" 200 NoError 123456 789012 300 200 \"http://referrer.com\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\" versionID123 hostID123 SigV4 TLS_AES_256_GCM_SHA384 AuthType123 hostHeader123 TLSv1.2",
			map[string]string{
				"aws.s3access.bucket_owner": "bucketOwner",
				"aws.s3access.bucket":       "myBucket",
				"timestamp":                 "18/Jun/2024:12:34:56 +0000",
				"client.address":            "192.168.1.1",
				"client.user.id":            "user12345",
				"aws.s3access.request_id":   "requestID12345",
				"aws.s3access.operation":    "REST.GET.OBJECT",
				"aws.s3access.key":          "objectKey",
				"aws.s3access.request_uri":  "GET https://127.0.0.1 HTTP/1.1",
				"http.request.method":       "GET",
				"url.original":              "https://127.0.0.1",
				"http.version":              "1.1",

				"http.response.status_code":        "200",
				"aws.s3access.error_code":          "NoError",
				"aws.s3access.bytes_sent":          "123456",
				"aws.s3access.object_size":         "789012",
				"aws.s3access.total_time":          "300",
				"aws.s3access.turn_around_time":    "200",
				"http.request.referrer":            "http://referrer.com",
				"user_agent.original":              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
				"aws.s3access.version_id":          "versionID123",
				"aws.s3access.host_id":             "hostID123",
				"aws.s3access.signature_version":   "SigV4",
				"tls.cipher":                       "TLS_AES_256_GCM_SHA384",
				"aws.s3access.authentication_type": "AuthType123",
				"aws.s3access.host_header":         "hostHeader123",
				"aws.s3access.tls_version":         "TLSv1.2",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g := grok.NewWithPatterns(patterns.AWS)
			require.NoError(t, g.Compile(tt.Pattern, true))

			res, err := g.ParseString(tt.Text)
			require.NoError(t, err)

			require.Equal(t, len(tt.ExpectedMatches), len(res))

			for k, v := range tt.ExpectedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equal(t, v, val)
			}
		})
	}
}
