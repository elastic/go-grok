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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWithPatterns_Firewalls(t *testing.T) {
	testCases := []struct {
		Name            string
		Pattern         string
		Text            string
		ExpectedMatches map[string]string
	}{
		{
			"NETSCREENSESSIONLOG",
			`%{NETSCREENSESSIONLOG}`,
			`Mar 15 12:34:56 192.168.1.1 observer1: NetScreen device_id=NS_100 system-id-1234(starting_session): start_time="2024-06-18T12:34:56" duration=3600 policy_id=100 service=http proto=6 src zone=trust dst zone=untrust action=allow sent=1024 rcvd=2048 src=192.168.1.100 dst=203.0.113.1 src_port=1234 dst_port=80 src-xlated ip=203.0.113.2 port=5678 dst-xlated ip=192.168.1.200 port=4321 session_id=98765 reason="session timeout"`,
			map[string]string{
				"timestamp":                    "Mar 15 12:34:56",
				"observer.hostname":            "192.168.1.1",
				"observer.name":                "observer1",
				"observer.product":             "NetScreen",
				"netscreen.device_id":          "NS_100",
				"event.code":                   "1234",
				"netscreen.session.type":       "starting_session",
				"netscreen.session.start_time": "2024-06-18T12:34:56",
				"netscreen.session.duration":   "3600",
				"netscreen.policy_id":          "100",
				"netscreen.service":            "http",
				"netscreen.protocol_number":    "6",
				"observer.ingress.zone":        "trust",
				"observer.egress.zone":         "untrust",
				"event.action":                 "allow",
				"source.bytes":                 "1024",
				"destination.bytes":            "2048",
				"source.address":               "192.168.1.100",
				"destination.address":          "203.0.113.1",
				"source.port":                  "1234",
				"destination.port":             "80",
				"source.nat.ip":                "203.0.113.2",
				"source.nat.port":              "5678",
				"destination.nat.ip":           "192.168.1.200",
				"destination.nat.port":         "4321",
				"netscreen.session.id":         "98765",
				"netscreen.session.reason":     "\"session timeout\"",
			},
		},
		{
			"CISCO_TAGGED_SYSLOG",
			`%{CISCO_TAGGED_SYSLOG}`,
			`<14>Jun 18 12:34:56 hostname : %ASA-6-302013: Built outbound TCP connection`,
			map[string]string{
				"log.syslog.priority": "14",
				"timestamp":           "Jun 18 12:34:56",
				"host.name":           "hostname",
				"cisco.asa.tag":       "ASA-6-302013",
			},
		},
		{
			"CISCOTAG",
			`%{CISCOTAG}`,
			`ABCD12EF-12345-ABC_123`,
			map[string]string{
				"CISCOTAG": "ABCD12EF-12345-ABC_123",
			},
		},
		{
			"CISCOTIMESTAMP",
			`%{CISCOTIMESTAMP}`,
			`Jun 18 12:34:56`,
			map[string]string{
				"CISCOTIMESTAMP": "Jun 18 12:34:56",
			},
		},
		{
			"CISCO_REASON",
			`%{CISCO_REASON}`,
			`DNS Query`,
			map[string]string{
				"CISCO_REASON": "DNS Query",
			},
		},
		{
			"CISCO_DIRECTION",
			`%{CISCO_DIRECTION}`,
			`outbound`,
			map[string]string{
				"CISCO_DIRECTION": "outbound",
			},
		},
		{
			"CISCO_INTERVAL",
			`%{CISCO_INTERVAL}`,
			`30-second interval`,
			map[string]string{
				"CISCO_INTERVAL": "30-second interval",
			},
		},
		{
			"CISCO_XLATE_TYPE",
			`%{CISCO_XLATE_TYPE}`,
			`dynamic`,
			map[string]string{
				"CISCO_XLATE_TYPE": "dynamic",
			},
		},
		{
			"IPTABLES_TCP_FLAGS",
			`%{IPTABLES_TCP_FLAGS}`,
			`SYN ACK PSH `,
			map[string]string{
				"IPTABLES_TCP_FLAGS": "SYN ACK PSH ",
			},
		},
		{
			"IPTABLES_TCP_PART",
			`%{IPTABLES_TCP_PART}`,
			`SEQ=12345 ACK=67890 WINDOW=29200 RES=0x00 SYN ACK PSH `,
			map[string]string{
				"iptables.tcp.seq":           "12345",
				"iptables.tcp.ack":           "67890",
				"iptables.tcp.window":        "29200",
				"iptables.tcp_reserved_bits": "00",
				"iptables.tcp.flags":         "SYN ACK PSH ",
			},
		},
		{
			"IPTABLES4_FRAG",
			`%{IPTABLES4_FRAG}`,
			`DF MF CE `,
			map[string]string{
				"IPTABLES4_FRAG": "DF MF CE",
			},
		},
		{
			"IPTABLES4_PART",
			`%{IPTABLES4_PART}`,
			`SRC=192.168.0.1 DST=192.168.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54321 DF FRAG: 0`,
			map[string]string{
				"source.address":           "192.168.0.1",
				"destination.address":      "192.168.0.2",
				"iptables.length":          "60",
				"iptables.tos":             "00",
				"iptables.precedence_bits": "00",
				"iptables.ttl":             "64",
				"iptables.id":              "54321",
				"iptables.fragment_flags":  "DF",
				"iptables.fragment_offset": "0",
			},
		},
		{
			"IPTABLES6_PART",
			`%{IPTABLES6_PART}`,
			`SRC=2001:0db8:85a3:0000:0000:8a2e:0370:7334 DST=2001:0db8:85a3:0000:0000:8a2e:0370:7335 LEN=100 TC=0x01 HOPLIMIT=64 FLOWLBL=12345`,
			map[string]string{
				"source.address":      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
				"destination.address": "2001:0db8:85a3:0000:0000:8a2e:0370:7335",
				"iptables.length":     "100",
				"iptables.tos":        "01",
				"iptables.ttl":        "64",
				"iptables.flow_label": "12345",
			},
		},
		{
			"IPTABLES",
			`%{IPTABLES}`,
			`IN=eth0 OUT=eth1 MAC=00:0a:95:9d:68:16:00:0a:95:9d:68:17 SRC=192.168.1.1 DST=192.168.1.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54321 DF PROTO=TCP SPT=12345 DPT=80 SEQ=0 ACK=0 WINDOW=65535 RES=0x00 SYN `,
			map[string]string{
				"observer.ingress.interface.name": "eth0",
				"observer.egress.interface.name":  "eth1",
				"destination.mac":                 "00:0a:95:9d:68:16",
				"source.mac":                      "00:0a:95:9d:68:17",
				"source.address":                  "192.168.1.1",
				"destination.address":             "192.168.1.2",
				"iptables.length":                 "60",
				"iptables.tos":                    "00",
				"iptables.precedence_bits":        "00",
				"iptables.ttl":                    "64",
				"iptables.id":                     "54321",
				"iptables.fragment_flags":         "DF",
				"network.transport":               "TCP",
				"source.port":                     "12345",
				"destination.port":                "80",
				"iptables.tcp.seq":                "0",
				"iptables.tcp.ack":                "0",
				"iptables.tcp.window":             "65535",
				"iptables.tcp_reserved_bits":      "00",
				"iptables.tcp.flags":              "SYN ",
			},
		},
		{
			"SHOREWALL",
			"%{SHOREWALL}",
			`Jun 18 12:34:56 myhost Shorewall:net2loc:DROP IN=eth0 OUT=eth1 MAC=00:0a:95:9d:68:16:00:0a:95:9d:68:17 SRC=192.168.1.1 DST=192.168.1.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54321 DF PROTO=TCP SPT=12345 DPT=80 SEQ=0 ACK=0 WINDOW=65535 RES=0x00 SYN `,
			map[string]string{
				"timestamp":                       "Jun 18 12:34:56",
				"observer.hostname":               "myhost",
				"shorewall.firewall.type":         "net2loc",
				"shorewall.firewall.action":       "DROP",
				"observer.ingress.interface.name": "eth0",
				"observer.egress.interface.name":  "eth1",
				"destination.mac":                 "00:0a:95:9d:68:16",
				"source.mac":                      "00:0a:95:9d:68:17",
				"source.address":                  "192.168.1.1",
				"destination.address":             "192.168.1.2",
				"iptables.length":                 "60",
				"iptables.tos":                    "00",
				"iptables.precedence_bits":        "00",
				"iptables.ttl":                    "64",
				"iptables.id":                     "54321",
				"iptables.fragment_flags":         "DF",
				"network.transport":               "TCP",
				"source.port":                     "12345",
				"destination.port":                "80",
				"iptables.tcp.seq":                "0",
				"iptables.tcp.ack":                "0",
				"iptables.tcp.window":             "65535",
				"iptables.tcp_reserved_bits":      "00",
				"iptables.tcp.flags":              "SYN ",
			},
		},
		{
			"SFW2_LOG_PREFIX",
			"%{SFW2_LOG_PREFIX}",
			`SFW2-INext-DROP`,
			map[string]string{
				"suse.firewall.action": "DROP",
			},
		},
		{
			"SFW2",
			"%{SFW2}",
			`2023-06-26T12:34:56 observer-hostname SFW2-INext-DROP IN=eth0 OUT=eth1 MAC=00:0a:95:9d:68:16:00:0a:95:9d:68:17 SRC=192.168.1.1 DST=192.168.1.2 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=54321 DF PROTO=TCP SPT=12345 DPT=80 SEQ=0 ACK=0 WINDOW=65535 RES=0x00 SYN `,
			map[string]string{
				"suse.firewall.action":            "DROP",
				"observer.ingress.interface.name": "eth0",
				"observer.egress.interface.name":  "eth1",
				"destination.mac":                 "00:0a:95:9d:68:16",
				"source.mac":                      "00:0a:95:9d:68:17",
				"source.address":                  "192.168.1.1",
				"destination.address":             "192.168.1.2",
				"iptables.length":                 "60",
				"iptables.tos":                    "00",
				"iptables.precedence_bits":        "00",
				"iptables.ttl":                    "64",
				"iptables.id":                     "54321",
				"iptables.fragment_flags":         "DF",
				"network.transport":               "TCP",
				"source.port":                     "12345",
				"destination.port":                "80",
				"iptables.tcp.seq":                "0",
				"iptables.tcp.ack":                "0",
				"iptables.tcp.window":             "65535",
				"iptables.tcp_reserved_bits":      "00",
				"iptables.tcp.flags":              "SYN ",

				"timestamp":                "2023-06-26T12:34:56",
				"observer.hostname":        "observer-hostname",
				"suse.firewall.log_prefix": "SFW2-INext-DROP",
			},
		},
		{
			"CISCO_HITCOUNT_INTERVAL",
			"%{CISCO_HITCOUNT_INTERVAL}",
			`hit-cnt 1234 10-second interval`,
			map[string]string{
				"cisco.asa.hit_count": "1234",
				"cisco.asa.interval":  "10",
			},
		},
		{
			"CISCO_SRC_IP_USER",
			"%{CISCO_SRC_IP_USER}",
			`eth0:192.168.1.1(jdoe)`,
			map[string]string{
				"observer.ingress.interface.name": "eth0",
				"source.address":                  "192.168.1.1",
				"source.user.name":                "jdoe",
			},
		},
		{
			"CISCO_DST_IP_USER",
			"%{CISCO_DST_IP_USER}",
			`eth1:10.0.0.1(jsmith)`,
			map[string]string{
				"observer.egress.interface.name": "eth1",
				"destination.address":            "10.0.0.1",
				"destination.user.name":          "jsmith",
			},
		},
		{
			"CISCO_SRC_HOST_PORT_USER",
			"%{CISCO_SRC_HOST_PORT_USER}",
			`eth0:192.168.1.1/80(jdoe)`,
			map[string]string{
				"observer.ingress.interface.name": "eth0",
				"source.address":                  "192.168.1.1",
				"source.port":                     "80",
				"source.user.name":                "jdoe",
			},
		},
		{
			"CISCO_DST_HOST_PORT_USER",
			"%{CISCO_DST_HOST_PORT_USER}",
			`eth1:10.0.0.1/443(jsmith)`,
			map[string]string{
				"observer.egress.interface.name": "eth1",
				"destination.address":            "10.0.0.1",
				"destination.port":               "443",
				"destination.user.name":          "jsmith",
			},
		},
		{
			"CISCOFW104001",
			"%{CISCOFW104001}",
			`(Primary) Switching to ACTIVE - High Availability`,
			map[string]string{
				"event.reason": "High Availability",
			},
		},
		{
			"CISCOFW104002",
			"%{CISCOFW104002}",
			`(Secondary) Switching to STANDBY - Manual Intervention`,
			map[string]string{
				"event.reason": "Manual Intervention",
			},
		},
		{
			"CISCOFW104003",
			"%{CISCOFW104003}",
			`(Primary) Switching to FAILED.`,
			map[string]string{},
		},
		{
			"CISCOFW104004",
			"%{CISCOFW104004}",
			`(Secondary) Switching to OK.`,
			map[string]string{},
		},
		{
			"CISCOFW105003",
			"%{CISCOFW105003}",
			`(Primary) Monitoring on interface GigabitEthernet0/1 waiting`,
			map[string]string{
				"network.interface.name": "GigabitEthernet0/1",
			},
		},
		{
			"CISCOFW105004",
			"%{CISCOFW105004}",
			`(Secondary) Monitoring on interface GigabitEthernet0/2 normal`,
			map[string]string{
				"network.interface.name": "GigabitEthernet0/2",
			},
		},
		{
			"CISCOFW105005",
			"%{CISCOFW105005}",
			`(Primary) Lost Failover communications with mate on interface GigabitEthernet0/3`,
			map[string]string{
				"network.interface.name": "GigabitEthernet0/3",
			},
		},
		{
			"CISCOFW105008",
			"%{CISCOFW105008}",
			`(Secondary) Testing interface GigabitEthernet0/4`,
			map[string]string{
				"network.interface.name": "GigabitEthernet0/4",
			},
		},
		{
			"CISCOFW105009",
			"%{CISCOFW105009}",
			`(Primary) Testing on interface GigabitEthernet0/5 Passed`,
			map[string]string{
				"network.interface.name": "GigabitEthernet0/5",
			},
		},

		{
			"CISCOFW106001",
			"%{CISCOFW106001}",
			`Inbound TCP connection permitted from 192.168.1.1/12345 to 10.0.0.1/80 flags S on interface eth0`,
			map[string]string{
				"cisco.asa.network.direction":    "Inbound",
				"cisco.asa.network.transport":    "TCP",
				"cisco.asa.outcome":              "permitted",
				"source.address":                 "192.168.1.1",
				"source.port":                    "12345",
				"destination.address":            "10.0.0.1",
				"destination.port":               "80",
				"cisco.asa.tcp_flags":            "S",
				"observer.egress.interface.name": "eth0",
			},
		},
		{
			"CISCOFW106006_106007_106010",
			"%{CISCOFW106006_106007_106010}",
			`denied inbound UDP src 192.168.1.1/12345 to 10.0.0.1/80 due to No matching connection`,
			map[string]string{
				"cisco.asa.outcome":           "denied",
				"cisco.asa.network.direction": "inbound",
				"cisco.asa.network.transport": "UDP",
				"source.address":              "192.168.1.1",
				"source.port":                 "12345",
				"destination.address":         "10.0.0.1",
				"destination.port":            "80",
				"event.reason":                "No matching connection",
			},
		},
		{
			"CISCOFW106014",
			"%{CISCOFW106014}",
			`denied outbound ICMP src eth0:192.168.1.1(jdoe) dst eth1:10.0.0.1(jsmith) (type 8, code 0)`,
			map[string]string{
				"cisco.asa.outcome":               "denied",
				"cisco.asa.network.direction":     "outbound",
				"cisco.asa.network.transport":     "ICMP",
				"observer.ingress.interface.name": "eth0",
				"source.address":                  "192.168.1.1",
				"source.user.name":                "jdoe",
				"observer.egress.interface.name":  "eth1",
				"destination.address":             "10.0.0.1",
				"destination.user.name":           "jsmith",
				"cisco.asa.icmp_type":             "8",
				"cisco.asa.icmp_code":             "0",
			},
		},
		{
			"CISCOFW106015",
			"%{CISCOFW106015}",
			`requested TCP (ACL-1) from 192.168.1.1/12345 to 10.0.0.1/80 flags S on interface eth0`,
			map[string]string{
				"cisco.asa.outcome":              "requested",
				"cisco.asa.network.transport":    "TCP",
				"cisco.asa.rule_name":            "ACL-1",
				"source.address":                 "192.168.1.1",
				"source.port":                    "12345",
				"destination.address":            "10.0.0.1",
				"destination.port":               "80",
				"cisco.asa.tcp_flags":            "S",
				"observer.egress.interface.name": "eth0",
			},
		},
		{
			"CISCOFW106021",
			"%{CISCOFW106021}",
			`permitted TCP reverse path check from 192.168.1.1 to 10.0.0.1 on interface eth0`,
			map[string]string{
				"cisco.asa.outcome":              "permitted",
				"cisco.asa.network.transport":    "TCP",
				"source.address":                 "192.168.1.1",
				"destination.address":            "10.0.0.1",
				"observer.egress.interface.name": "eth0",
			},
		},
		{
			"CISCOFW106100_2_3",
			"%{CISCOFW106100_2_3}",
			`access-list ACL permitted TCP for user 'jsmith' eth0/192.168.1.1(12345) -> eth1/10.0.0.1(80) hit-cnt 1234 10-second interval [hash1, hash2]`,
			map[string]string{
				"cisco.asa.rule_name":             "ACL",
				"cisco.asa.outcome":               "permitted",
				"cisco.asa.network.transport":     "TCP",
				"user.name":                       "jsmith",
				"observer.ingress.interface.name": "eth0",
				"source.address":                  "192.168.1.1",
				"source.port":                     "12345",
				"observer.egress.interface.name":  "eth1",
				"destination.address":             "10.0.0.1",
				"destination.port":                "80",
				"cisco.asa.hit_count":             "1234",
				"cisco.asa.interval":              "10",
				"metadata.cisco.asa.hashcode1":    "hash1",
				"metadata.cisco.asa.hashcode2":    "hash2",
			},
		},
		{
			"CISCOFW106100",
			"%{CISCOFW106100}",
			`access-list ACL permitted UDP eth0/192.168.1.1(12345) -> eth1/10.0.0.1(80) hit-cnt 50 5-second interval [hash1, hash2]`,
			map[string]string{
				"cisco.asa.rule_name":             "ACL",
				"cisco.asa.outcome":               "permitted",
				"cisco.asa.network.transport":     "UDP",
				"observer.ingress.interface.name": "eth0",
				"source.address":                  "192.168.1.1",
				"source.port":                     "12345",
				"observer.egress.interface.name":  "eth1",
				"destination.address":             "10.0.0.1",
				"destination.port":                "80",
				"cisco.asa.hit_count":             "50",
				"CISCO_INTERVAL":                  "5-second interval",
			},
		},
		{
			"CISCOFW304001",
			"%{CISCOFW304001}",
			`192.168.1.1(jdoe) Accessed URL 10.0.0.1:http://example.com`,
			map[string]string{
				"source.address":      "192.168.1.1",
				"source.user.name":    "jdoe",
				"destination.address": "10.0.0.1",
				"url.original":        "http://example.com",
			},
		},
		{
			"CISCOFW110002",
			"%{CISCOFW110002}",
			`Timeout for TCP from eth0:192.168.1.1/12345 to 10.0.0.1/80`,
			map[string]string{
				"event.reason":                    "Timeout",
				"cisco.asa.network.transport":     "TCP",
				"observer.ingress.interface.name": "eth0",
				"source.address":                  "192.168.1.1",
				"source.port":                     "12345",
				"destination.address":             "10.0.0.1",
				"destination.port":                "80",
			},
		},
		{
			"CISCOFW302010",
			"%{CISCOFW302010}",
			`50 in use, 100 most used`,
			map[string]string{
				"cisco.asa.connections.in_use":    "50",
				"cisco.asa.connections.most_used": "100",
			},
		},
		{
			"CISCOFW302013_302014_302015_302016",
			"%{CISCOFW302013_302014_302015_302016}",
			`Built inbound TCP connection 12345 for eth0:192.168.1.1/12345 (192.168.1.100/12345) to eth1:10.0.0.1/80 (10.0.0.100/80) duration 0:01:30 bytes 1500`,
			map[string]string{
				"cisco.asa.outcome":               "Built",
				"cisco.asa.network.direction":     "inbound",
				"cisco.asa.connection_id":         "12345",
				"observer.ingress.interface.name": "eth0",
				"source.address":                  "192.168.1.1",
				"source.port":                     "12345",
				"source.nat.ip":                   "192.168.1.100",
				"source.nat.port":                 "12345",
				"observer.egress.interface.name":  "eth1",
				"destination.address":             "10.0.0.1",
				"destination.port":                "80",
				"destination.nat.ip":              "10.0.0.100",
				"destination.nat.port":            "80",
				"cisco.asa.duration":              "0:01:30",
				"network.bytes":                   "1500",
			},
		},
		{
			"CISCOFW302020_302021",
			"%{CISCOFW302020_302021}",
			`permitted inbound TCP connection for faddr 10.0.0.1/1(jsmith) gaddr 192.168.1.100/8 laddr 192.168.1.1/6 (jdoe)`,
			map[string]string{
				"cisco.asa.outcome":           "permitted",
				"cisco.asa.network.direction": "inbound",
				"cisco.asa.network.transport": "TCP",
				"destination.address":         "10.0.0.1",
				"cisco.asa.icmp_seq":          "1",
				"destination.user.name":       "jsmith",
				"source.nat.ip":               "192.168.1.100",
				"cisco.asa.icmp_type":         "8",
				"source.address":              "192.168.1.1",
				"source.user.name":            "jdoe",
			},
		},
		{
			"CISCOFW305011",
			"%{CISCOFW305011}",
			`Built static TCP translation from eth0:192.168.1.1/12345(jdoe) to eth1:10.0.0.1/80`,
			map[string]string{
				"cisco.asa.outcome":               "Built",
				"CISCO_XLATE_TYPE":                "static",
				"cisco.asa.network.transport":     "TCP",
				"observer.ingress.interface.name": "eth0",
				"source.address":                  "192.168.1.1",
				"source.port":                     "12345",
				"source.user.name":                "jdoe",
				"observer.egress.interface.name":  "eth1",
				"destination.address":             "10.0.0.1",
				"destination.port":                "80",
			},
		},
		{
			"CISCOFW313001_313004_313008",
			"%{CISCOFW313001_313004_313008}",
			`denied ICMP type=3, code=2 from 192.168.1.1 on interface eth0 to 10.0.0.1`,
			map[string]string{
				"cisco.asa.outcome":              "denied",
				"cisco.asa.network.transport":    "ICMP",
				"cisco.asa.icmp_type":            "3",
				"cisco.asa.icmp_code":            "2",
				"source.address":                 "192.168.1.1",
				"observer.egress.interface.name": "eth0",
				"destination.address":            "10.0.0.1",
			},
		},
		{
			"CISCOFW313005",
			"%{CISCOFW313005}",
			`Timeout for TCP error message: echo src eth0:192.168.1.1(jdoe) dst eth1:10.0.0.1(jsmith) (type 3, code 2) on eth0 interface. Original IP payload: TCP src 192.168.1.1/12345(jdoe) dst 10.0.0.1/80(jsmith)`,
			map[string]string{
				"event.reason":                                        "Timeout",
				"cisco.asa.network.transport":                         "TCP",
				"cisco.asa.icmp_type":                                 "3",
				"cisco.asa.icmp_code":                                 "2",
				"observer.ingress.interface.name":                     "eth0",
				"source.address":                                      "192.168.1.1",
				"source.user.name":                                    "jdoe",
				"observer.egress.interface.name":                      "eth1",
				"destination.address":                                 "10.0.0.1",
				"destination.user.name":                               "jsmith",
				"cisco.asa.original_ip_payload.network.transport":     "TCP",
				"cisco.asa.original_ip_payload.source.address":        "192.168.1.1",
				"cisco.asa.original_ip_payload.source.port":           "12345",
				"cisco.asa.original_ip_payload.source.user.name":      "jdoe",
				"cisco.asa.original_ip_payload.destination.address":   "10.0.0.1",
				"cisco.asa.original_ip_payload.destination.port":      "80",
				"cisco.asa.original_ip_payload.destination.user.name": "jsmith",
			},
		},
		{
			"CISCOFW321001",
			"%{CISCOFW321001}",
			`Resource 'sessions' limit of 1000 reached for system`,
			map[string]string{
				"cisco.asa.resource.name":  "sessions",
				"cisco.asa.resource.limit": "1000",
			},
		},
		{
			"CISCOFW402117",
			"%{CISCOFW402117}",
			`IPSec: Received a non-IPSec packet (protocol= TCP) from 192.168.1.1 to 10.0.0.1`,
			map[string]string{
				"cisco.asa.network.type":      "IPSec",
				"cisco.asa.network.transport": "TCP",
				"source.address":              "192.168.1.1",
				"destination.address":         "10.0.0.1",
			},
		},
		{
			"CISCOFW402119",
			"%{CISCOFW402119}",
			`IPSec: Received an ESP packet (SPI= 0x00001234, sequence number= 1) from 192.168.1.1 (user= jdoe) to 10.0.0.1 that failed anti-replay checking.`,
			map[string]string{
				"cisco.asa.network.type":   "IPSec",
				"cisco.asa.ipsec.protocol": "ESP",
				"cisco.asa.ipsec.spi":      "0x00001234",
				"cisco.asa.ipsec.seq_num":  "1",
				"source.address":           "192.168.1.1",
				"source.user.name":         "jdoe",
				"destination.address":      "10.0.0.1",
			},
		},
		{
			"CISCOFW419001",
			"%{CISCOFW419001}",
			`denied TCP packet from eth0:192.168.1.1/12345 to eth1:10.0.0.1/80, reason: ACL-5`,
			map[string]string{
				"cisco.asa.outcome":               "denied",
				"cisco.asa.network.transport":     "TCP",
				"observer.ingress.interface.name": "eth0",
				"source.address":                  "192.168.1.1",
				"source.port":                     "12345",
				"observer.egress.interface.name":  "eth1",
				"destination.address":             "10.0.0.1",
				"destination.port":                "80",
				"event.reason":                    "ACL-5",
			},
		},
		{
			"CISCOFW500004",
			"%{CISCOFW500004}",
			`DNS Query for protocol=TCP, from 192.168.1.1/80 to 192.168.2.2/30`,
			map[string]string{
				"destination.port":    "30",
				"destination.address": "192.168.2.2",
				"source.port":         "80",
				"source.address":      "192.168.1.1",
				"event.reason":        "DNS Query",
			},
		},
		{
			"CISCOFW602303_602304",
			"%{CISCOFW602303_602304}",
			`TYPE: An inbound TUN SA (SPI=spi) between 192.168.1.1 and 192.168.1.2 (user=jdoe) has been denied`,
			map[string]string{
				"destination.address":         "192.168.1.2",
				"source.address":              "192.168.1.1",
				"cisco.asa.network.type":      "TYPE",
				"cisco.asa.network.direction": "inbound",
				"cisco.asa.ipsec.tunnel_type": "TUN",
				"cisco.asa.ipsec.spi":         "spi",
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.Name, func(t *testing.T) {
			g, err := grok.NewWithPatterns(patterns.Firewalls)
			require.NoError(t, err)
			require.NoError(t, g.Compile(tt.Pattern, false))

			res, err := g.ParseString(tt.Text)
			require.NoError(t, err)

			if len(tt.ExpectedMatches) > len(res) {
				for k := range tt.ExpectedMatches {
					_, ok := res[k]
					assert.Truef(t, ok, "key not found %q", k)
				}
			}

			for k, v := range tt.ExpectedMatches {
				val, found := res[k]
				require.True(t, found, "Key %q not found", k)
				require.Equalf(t, v, val, "Values not equal for key. Expected %q, have %q", k, v, val)
			}
		})
	}
}
