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
 * @file	data-control-types.h
 * @brief	This is the header file for data types of the data-control.
 */

#ifndef _APPFW_DATA_CONTROL_TYPES_H_
#define _APPFW_DATA_CONTROL_TYPES_H_

#include <errno.h>

#ifdef __GNUC__
#   ifndef EXPORT_API
#       define EXPORT_API __attribute__((visibility("default")))
#   endif
#else
#   define EXPORT_API
#endif

/**
 * @brief Provider handle
 */
typedef struct datacontrol_s *datacontrol_h;

/**
 * @brief Enumerations of different types of columns in an SQL table.
 */
typedef enum
{
	DATACONTROL_SQL_COLUMN_TYPE_UNDEFINED = 0,
	DATACONTROL_SQL_COLUMN_TYPE_INT64,
	DATACONTROL_SQL_COLUMN_TYPE_DOUBLE,
	DATACONTROL_SQL_COLUMN_TYPE_TEXT,
	DATACONTROL_SQL_COLUMN_TYPE_BLOB,
	DATACONTROL_SQL_COLUMN_TYPE_NULL
} datacontrol_sql_column_type;

/**
 * @brief Enumerations of the various error-codes an API can return.
 */
typedef enum
{
	DATACONTROL_ERROR_NONE = 0, /**< Successful */
	DATACONTROL_ERROR_OUT_OF_MEMORY = -ENOMEM, /**< Out of memory */
	DATACONTROL_ERROR_IO_ERROR = -EIO, /**< I/O error */
	DATACONTROL_ERROR_INVALID_PARAMETER = -EINVAL, /**< Invalid parameter */
	DATACONTROL_ERROR_PERMISSION_DENIED = -EACCES, /**< Permission denied */
	DATACONTROL_ERROR_MAX_EXCEEDED  = -EMSGSIZE /**< Too long argument */
} datacontrol_error_e;

#endif /* _APPFW_DATA_CONTROL_TYPES_H_ */

