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

package patterns

// Nagios patterns ported from elastic/elasticsearch ecs-v1/nagios.
var Nagios map[string]string = map[string]string{
	"NAGIOSTIME": `\[%{NUMBER:timestamp}\]`,

	"NAGIOS_TYPE_CURRENT_SERVICE_STATE": "CURRENT SERVICE STATE",
	"NAGIOS_TYPE_CURRENT_HOST_STATE":    "CURRENT HOST STATE",

	"NAGIOS_TYPE_SERVICE_NOTIFICATION": "SERVICE NOTIFICATION",
	"NAGIOS_TYPE_HOST_NOTIFICATION":    "HOST NOTIFICATION",

	"NAGIOS_TYPE_SERVICE_ALERT": "SERVICE ALERT",
	"NAGIOS_TYPE_HOST_ALERT":    "HOST ALERT",

	"NAGIOS_TYPE_SERVICE_FLAPPING_ALERT": "SERVICE FLAPPING ALERT",
	"NAGIOS_TYPE_HOST_FLAPPING_ALERT":    "HOST FLAPPING ALERT",

	"NAGIOS_TYPE_SERVICE_DOWNTIME_ALERT": "SERVICE DOWNTIME ALERT",
	"NAGIOS_TYPE_HOST_DOWNTIME_ALERT":    "HOST DOWNTIME ALERT",

	"NAGIOS_TYPE_PASSIVE_SERVICE_CHECK": "PASSIVE SERVICE CHECK",
	"NAGIOS_TYPE_PASSIVE_HOST_CHECK":    "PASSIVE HOST CHECK",

	"NAGIOS_TYPE_SERVICE_EVENT_HANDLER": "SERVICE EVENT HANDLER",
	"NAGIOS_TYPE_HOST_EVENT_HANDLER":    "HOST EVENT HANDLER",

	"NAGIOS_TYPE_EXTERNAL_COMMAND":     "EXTERNAL COMMAND",
	"NAGIOS_TYPE_TIMEPERIOD_TRANSITION": "TIMEPERIOD TRANSITION",

	"NAGIOS_EC_DISABLE_SVC_CHECK":              "DISABLE_SVC_CHECK",
	"NAGIOS_EC_ENABLE_SVC_CHECK":               "ENABLE_SVC_CHECK",
	"NAGIOS_EC_DISABLE_HOST_CHECK":             "DISABLE_HOST_CHECK",
	"NAGIOS_EC_ENABLE_HOST_CHECK":              "ENABLE_HOST_CHECK",
	"NAGIOS_EC_PROCESS_SERVICE_CHECK_RESULT":   "PROCESS_SERVICE_CHECK_RESULT",
	"NAGIOS_EC_PROCESS_HOST_CHECK_RESULT":      "PROCESS_HOST_CHECK_RESULT",
	"NAGIOS_EC_SCHEDULE_SERVICE_DOWNTIME":      "SCHEDULE_SERVICE_DOWNTIME",
	"NAGIOS_EC_SCHEDULE_HOST_DOWNTIME":         "SCHEDULE_HOST_DOWNTIME",
	"NAGIOS_EC_DISABLE_HOST_SVC_NOTIFICATIONS": "DISABLE_HOST_SVC_NOTIFICATIONS",
	"NAGIOS_EC_ENABLE_HOST_SVC_NOTIFICATIONS":  "ENABLE_HOST_SVC_NOTIFICATIONS",
	"NAGIOS_EC_DISABLE_HOST_NOTIFICATIONS":     "DISABLE_HOST_NOTIFICATIONS",
	"NAGIOS_EC_ENABLE_HOST_NOTIFICATIONS":      "ENABLE_HOST_NOTIFICATIONS",
	"NAGIOS_EC_DISABLE_SVC_NOTIFICATIONS":      "DISABLE_SVC_NOTIFICATIONS",
	"NAGIOS_EC_ENABLE_SVC_NOTIFICATIONS":       "ENABLE_SVC_NOTIFICATIONS",

	"NAGIOS_WARNING": `Warning:%{SPACE}%{GREEDYDATA:message}`,

	"NAGIOS_CURRENT_SERVICE_STATE": `%{NAGIOS_TYPE_CURRENT_SERVICE_STATE:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.name};%{DATA:service.state};%{DATA:nagios.log.state_type};%{INT:nagios.log.attempt:int};%{GREEDYDATA:message}`,
	"NAGIOS_CURRENT_HOST_STATE":    `%{NAGIOS_TYPE_CURRENT_HOST_STATE:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.state};%{DATA:nagios.log.state_type};%{INT:nagios.log.attempt:int};%{GREEDYDATA:message}`,

	"NAGIOS_SERVICE_NOTIFICATION": `%{NAGIOS_TYPE_SERVICE_NOTIFICATION:nagios.log.type}: %{DATA:user.name};%{DATA:host.hostname};%{DATA:service.name};%{DATA:service.state};%{DATA:nagios.log.notification_command};%{GREEDYDATA:message}`,
	"NAGIOS_HOST_NOTIFICATION":    `%{NAGIOS_TYPE_HOST_NOTIFICATION:nagios.log.type}: %{DATA:user.name};%{DATA:host.hostname};%{DATA:service.state};%{DATA:nagios.log.notification_command};%{GREEDYDATA:message}`,

	"NAGIOS_SERVICE_ALERT": `%{NAGIOS_TYPE_SERVICE_ALERT:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.name};%{DATA:service.state};%{DATA:nagios.log.state_type};%{INT:nagios.log.attempt:int};%{GREEDYDATA:message}`,
	"NAGIOS_HOST_ALERT":    `%{NAGIOS_TYPE_HOST_ALERT:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.state};%{DATA:nagios.log.state_type};%{INT:nagios.log.attempt:int};%{GREEDYDATA:message}`,

	"NAGIOS_SERVICE_FLAPPING_ALERT": `%{NAGIOS_TYPE_SERVICE_FLAPPING_ALERT:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.name};%{DATA:service.state};%{GREEDYDATA:message}`,
	"NAGIOS_HOST_FLAPPING_ALERT":    `%{NAGIOS_TYPE_HOST_FLAPPING_ALERT:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.state};%{GREEDYDATA:message}`,

	"NAGIOS_SERVICE_DOWNTIME_ALERT": `%{NAGIOS_TYPE_SERVICE_DOWNTIME_ALERT:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.name};%{DATA:service.state};%{GREEDYDATA:nagios.log.comment}`,
	"NAGIOS_HOST_DOWNTIME_ALERT":    `%{NAGIOS_TYPE_HOST_DOWNTIME_ALERT:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.state};%{GREEDYDATA:nagios.log.comment}`,

	"NAGIOS_PASSIVE_SERVICE_CHECK": `%{NAGIOS_TYPE_PASSIVE_SERVICE_CHECK:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.name};%{DATA:service.state};%{GREEDYDATA:nagios.log.comment}`,
	"NAGIOS_PASSIVE_HOST_CHECK":    `%{NAGIOS_TYPE_PASSIVE_HOST_CHECK:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.state};%{GREEDYDATA:nagios.log.comment}`,

	"NAGIOS_SERVICE_EVENT_HANDLER": `%{NAGIOS_TYPE_SERVICE_EVENT_HANDLER:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.name};%{DATA:service.state};%{DATA:nagios.log.state_type};%{DATA:nagios.log.event_handler_name}`,
	"NAGIOS_HOST_EVENT_HANDLER":    `%{NAGIOS_TYPE_HOST_EVENT_HANDLER:nagios.log.type}: %{DATA:host.hostname};%{DATA:service.state};%{DATA:nagios.log.state_type};%{DATA:nagios.log.event_handler_name}`,

	"NAGIOS_TIMEPERIOD_TRANSITION": `%{NAGIOS_TYPE_TIMEPERIOD_TRANSITION:nagios.log.type}: %{DATA:service.name};%{NUMBER:nagios.log.period_from:int};%{NUMBER:nagios.log.period_to:int}`,

	"NAGIOS_EC_LINE_DISABLE_SVC_CHECK":  `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_DISABLE_SVC_CHECK:nagios.log.command};%{DATA:host.hostname};%{DATA:service.name}`,
	"NAGIOS_EC_LINE_DISABLE_HOST_CHECK": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_DISABLE_HOST_CHECK:nagios.log.command};%{DATA:host.hostname}`,

	"NAGIOS_EC_LINE_ENABLE_SVC_CHECK":  `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_ENABLE_SVC_CHECK:nagios.log.command};%{DATA:host.hostname};%{DATA:service.name}`,
	"NAGIOS_EC_LINE_ENABLE_HOST_CHECK": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_ENABLE_HOST_CHECK:nagios.log.command};%{DATA:host.hostname}`,

	"NAGIOS_EC_LINE_PROCESS_SERVICE_CHECK_RESULT": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_PROCESS_SERVICE_CHECK_RESULT:nagios.log.command};%{DATA:host.hostname};%{DATA:service.name};%{DATA:service.state};%{GREEDYDATA:nagios.log.check_result}`,
	"NAGIOS_EC_LINE_PROCESS_HOST_CHECK_RESULT":    `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_PROCESS_HOST_CHECK_RESULT:nagios.log.command};%{DATA:host.hostname};%{DATA:service.state};%{GREEDYDATA:nagios.log.check_result}`,

	"NAGIOS_EC_LINE_DISABLE_HOST_SVC_NOTIFICATIONS": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_DISABLE_HOST_SVC_NOTIFICATIONS:nagios.log.command};%{GREEDYDATA:host.hostname}`,
	"NAGIOS_EC_LINE_DISABLE_HOST_NOTIFICATIONS":     `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_DISABLE_HOST_NOTIFICATIONS:nagios.log.command};%{GREEDYDATA:host.hostname}`,
	"NAGIOS_EC_LINE_DISABLE_SVC_NOTIFICATIONS":      `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_DISABLE_SVC_NOTIFICATIONS:nagios.log.command};%{DATA:host.hostname};%{GREEDYDATA:service.name}`,

	"NAGIOS_EC_LINE_ENABLE_HOST_SVC_NOTIFICATIONS": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_ENABLE_HOST_SVC_NOTIFICATIONS:nagios.log.command};%{GREEDYDATA:host.hostname}`,
	"NAGIOS_EC_LINE_ENABLE_HOST_NOTIFICATIONS":     `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_ENABLE_HOST_NOTIFICATIONS:nagios.log.command};%{GREEDYDATA:host.hostname}`,
	"NAGIOS_EC_LINE_ENABLE_SVC_NOTIFICATIONS":      `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_ENABLE_SVC_NOTIFICATIONS:nagios.log.command};%{DATA:host.hostname};%{GREEDYDATA:service.name}`,

	"NAGIOS_EC_LINE_SCHEDULE_HOST_DOWNTIME": `%{NAGIOS_TYPE_EXTERNAL_COMMAND:nagios.log.type}: %{NAGIOS_EC_SCHEDULE_HOST_DOWNTIME:nagios.log.command};%{DATA:host.hostname};%{NUMBER:nagios.log.start_time};%{NUMBER:nagios.log.end_time};%{NUMBER:nagios.log.fixed};%{NUMBER:nagios.log.trigger_id};%{NUMBER:nagios.log.duration:int};%{DATA:user.name};%{DATA:nagios.log.comment}`,

	"NAGIOSLOGLINE": `%{NAGIOSTIME} (?:%{NAGIOS_WARNING}|%{NAGIOS_CURRENT_SERVICE_STATE}|%{NAGIOS_CURRENT_HOST_STATE}|%{NAGIOS_SERVICE_NOTIFICATION}|%{NAGIOS_HOST_NOTIFICATION}|%{NAGIOS_SERVICE_ALERT}|%{NAGIOS_HOST_ALERT}|%{NAGIOS_SERVICE_FLAPPING_ALERT}|%{NAGIOS_HOST_FLAPPING_ALERT}|%{NAGIOS_SERVICE_DOWNTIME_ALERT}|%{NAGIOS_HOST_DOWNTIME_ALERT}|%{NAGIOS_PASSIVE_SERVICE_CHECK}|%{NAGIOS_PASSIVE_HOST_CHECK}|%{NAGIOS_SERVICE_EVENT_HANDLER}|%{NAGIOS_HOST_EVENT_HANDLER}|%{NAGIOS_TIMEPERIOD_TRANSITION}|%{NAGIOS_EC_LINE_DISABLE_SVC_CHECK}|%{NAGIOS_EC_LINE_ENABLE_SVC_CHECK}|%{NAGIOS_EC_LINE_DISABLE_HOST_CHECK}|%{NAGIOS_EC_LINE_ENABLE_HOST_CHECK}|%{NAGIOS_EC_LINE_PROCESS_HOST_CHECK_RESULT}|%{NAGIOS_EC_LINE_PROCESS_SERVICE_CHECK_RESULT}|%{NAGIOS_EC_LINE_SCHEDULE_HOST_DOWNTIME}|%{NAGIOS_EC_LINE_DISABLE_HOST_SVC_NOTIFICATIONS}|%{NAGIOS_EC_LINE_ENABLE_HOST_SVC_NOTIFICATIONS}|%{NAGIOS_EC_LINE_DISABLE_HOST_NOTIFICATIONS}|%{NAGIOS_EC_LINE_ENABLE_HOST_NOTIFICATIONS}|%{NAGIOS_EC_LINE_DISABLE_SVC_NOTIFICATIONS}|%{NAGIOS_EC_LINE_ENABLE_SVC_NOTIFICATIONS})`,
}
