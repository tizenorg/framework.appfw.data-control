//
// Copyright (c) 2013 Samsung Electronics Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the License);
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
//

/**
 * @file	data-control-internal.h
 * @brief	This is the header file for private keys of the data-control.
 */

#ifndef _APPFW_DATA_CONTROL_INTERNAL_H_
#define _APPFW_DATA_CONTROL_INTERNAL_H_

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "DATA_CONTROL"
#endif

#define MAX_LEN_DATACONTROL_REQ_TYPE  8
#define MAX_LEN_DATACONTROL_COLUMN_COUNT  8

#define OSP_K_LAUNCH_TYPE   "__OSP_LAUNCH_TYPE__"
#define OSP_K_ARG           "__OSP_ARGS__"
#define OSP_K_REQUEST_ID    "__OSP_REQUEST_ID__"
#define OSP_K_DATACONTROL_PROVIDER		"__OSP_DATACONTROL_PROVIDER__"
#define OSP_K_DATACONTROL_DATA			"__OSP_DATACONTROL_DATA__"
#define OSP_K_DATACONTROL_REQUEST_TYPE  "__OSP_DATACONTROL_REQUEST_TYPE__"
#define OSP_K_DATACONTROL_PROTOCOL_VERSION	"__OSP_DATACONTROL_PROTOCOL_VERSION__"
#define OSP_K_CALLER_TYPE   "__OSP_CALLER_TYPE__"

#define DATACONTROL_SELECT_STATEMENT 	"DATACONTROL_SELECT_STATEMENT"

#define DATACONTROL_EMPTY 		"NULL"
#define DATACONTROL_SELECT_EXTRA_COUNT		6  // data id, column count, where, order, page, per_page



#define OSP_V_LAUNCH_TYPE_DATACONTROL  	"datacontrol"
#define OSP_V_VERSION_2_1_0_3  "ver_2.1.0.3"
#define OSP_V_CALLER_TYPE_OSP  "osp"

#define DATACONTROL_REQUEST_FILE_PREFIX "datacontrol.request."
#define DATACONTROL_RESULT_FILE_PREFIX  "datacontrol.result."

#define READ_ONLY "readonly"
#define WRITE_ONLY "writeonly"

/**
 * @brief Enumerations of different type of data control requests.
 */
typedef enum
{
	DATACONTROL_TYPE_ERROR = -1,
	DATACONTROL_TYPE_UNDEFINED,
	DATACONTROL_TYPE_SQL_SELECT,
	DATACONTROL_TYPE_SQL_INSERT,
	DATACONTROL_TYPE_SQL_UPDATE,
	DATACONTROL_TYPE_SQL_DELETE,
	DATACONTROL_TYPE_MAP_GET,
	DATACONTROL_TYPE_MAP_SET,
	DATACONTROL_TYPE_MAP_ADD,
	DATACONTROL_TYPE_MAP_REMOVE,
	DATACONTROL_TYPE_MAX = 255
} datacontrol_request_type;

int
datacontrol_sql_set_cursor(const char *path);

int
_datacontrol_create_request_id(void);

#endif /* _APPFW_DATA_CONTROL_INTERNAL_H_ */

