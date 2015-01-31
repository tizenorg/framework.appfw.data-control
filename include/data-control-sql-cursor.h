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
 * @file	data-control-sql-cursor.h
 * @brief	This is the header file for the cursor of the SQL-friendly interface based data control.
 */

#ifndef _APPFW_DATA_CONTROL_SQL_ENUMERATOR_H_
#define _APPFW_DATA_CONTROL_SQL_ENUMERATOR_H_

#include <stdio.h>
#include "data-control-types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief	The structure type to represent a sql result set. This type can be used to enumerate through the result set of an SQL query.
 */
typedef struct
{
	int resultset_fd;
	int resultset_row_count;
	int resultset_col_count;
	int resultset_col_type_offset;
	int resultset_col_name_offset;
	int resultset_content_offset;
	int resultset_current_offset;
	int resultset_current_row_count;
	char* resultset_path;
} resultset_cursor;

/**
 * @brief		Creates a cursor to enumerate through an SQL result set
 *
 * @param [in]	path		The path of the file containing the SQL result set
 * @return		A pointer to struct @c resultset_cursor
 */
resultset_cursor* datacontrol_sql_get_cursor(const char *path);

/**
 * @brief		Moves the cursor to the first position
 *
 * @param [in]	cursor	Navigates the result of the request for the select operation
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 *
 * The following example demonstrates how to use the %datacontrol_sql_step_first() method.
 *
 * @code
 *
 *	void sql_select_response_cb(int request_id, datacontrol_h provider, resultset_cursor *cursor, bool provider_result, const char *error)
 *	{
 *		char person_name[32] = {0,};
 *		long long person_number = -1;
 *
 *		datacontrol_sql_step_first(cursor);
 *		datacontrol_sql_get_text_data(cursor, 0, person_name);
 *		datacontrol_sql_get_int64_data(cursor, 1, &person_number);
 *		printf("The person %s has the number %l", person_name, person_number);
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_sql_step_first(resultset_cursor *cursor);

/**
 * @brief		Moves the cursor to the last position
 *
 * @param [in]	cursor	Navigates the result of data control select request
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 *
 * The following example demonstrates how to use the %datacontrol_sql_step_last() method.
 *
 * @code
 *
 *	void sql_select_response_cb(int request_id, datacontrol_h provider, resultset_cursor *cursor, bool provider_result, const char *error)
 *	{
 *		char person_name[32] = {0,};
 *		long long person_number = -1;
 *
 *		datacontrol_sql_step_last(cursor);
 *		datacontrol_sql_get_text_data(cursor, 0, person_name);
 *		datacontrol_sql_get_int64_data(cursor, 1, &person_number);
 *		printf("The person %s has the number %l", person_name, person_number);
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_sql_step_last(resultset_cursor *cursor);

/**
 * @brief		Moves the cursor to the next position
 *
 * @param [in]	cursor	Navigates the result of the request for the select operation
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 *
 * The following example demonstrates how to use the %datacontrol_sql_step_next() method.
 *
 * @code
 *
 *	void sql_select_response_cb(int request_id, datacontrol_h provider, resultset_cursor *cursor, bool provider_result, const char *error)
 *	{
 *		char person_name[32] = {0,};
 *		long long person_number = -1;
 *		while (datacontrol_sql_step_next(cursor) == DATACONTROL_ERROR_NONE) {
 *			datacontrol_sql_get_text_data(cursor, 0, person_name);
 *			datacontrol_sql_get_int64_data(cursor, 1, &person_number);
 *			printf("The person %s has the number %l", person_name, person_number);
 *		}
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_sql_step_next(resultset_cursor *cursor);

/**
 * @brief		Moves the cursor to the previous position
 *
 * @param [in]	cursor	Navigates the result of the request for the select operation
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_sql_step_previous(resultset_cursor *cursor);

/**
 * @brief 	Gets the number of columns for this cursor
 *
 * @param [in]	cursor	Navigates the result of the request for the select operation
 * @return		The number of columns in the calling cursor
 */
EXPORT_API int datacontrol_sql_get_column_count(resultset_cursor *cursor);

/**
 * @brief		Gets the name of the column indicated by the specified index
 *
 * @param [in] 	cursor	Navigates the result of the request for the select operation
 * @param [in]	column_index		The index of the destination column
 * @param [out]	name			The name of the destination column
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 */
EXPORT_API int datacontrol_sql_get_column_name(resultset_cursor *cursor, int column_index, char *name);

/**
 * @brief		Gets the size of data in the column indicated by the specified index
 *
 * @param [in]	cursor	Navigates the result of the request for the select operation
 * @param [in]	column_index		The index of the destination column
 * @return		The size of data in the column indicated by the specified index. @n
 *				If an error is occurred, a negative value is returned.
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 */
EXPORT_API int datacontrol_sql_get_column_item_size(resultset_cursor *cursor, int column_index);

/**
 * @brief		Gets the type of the column indicated by the specified index
 *
 * @param [in]	cursor		Navigates the result of the request for the select operation
 * @param [in]	column_index	The index of the destination column
 * @param [out]	type			The type of the destination column
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 */
EXPORT_API int datacontrol_sql_get_column_item_type(resultset_cursor *cursor, int column_index, datacontrol_sql_column_type* type);

/**
 * @brief		Gets a blob data from the column indicated by the specified index
 *
 * @param [in]	cursor		Navigates the result of the request for the select operation
 * @param [in]	column_index	The index of the destination column
 * @param [out]	data			The blob value obtained from the column
 * @param [out]	size			The size of the data
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_MAX_EXCEEDED Too long argument
 */
EXPORT_API int datacontrol_sql_get_blob_data(resultset_cursor *cursor, int column_index, void *data, int size);

/**
 * @brief		Gets an int value from the column indicated by the specified index
 *
 * @param [in]	cursor		Navigates the result of the request for the select operation
 * @param [in]	column_index	The index of the destination column
 * @param [out]	data			The integer value obtained from the column
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_sql_get_int_data(resultset_cursor *cursor, int column_index, int *data);

/**
 * @brief		Gets a long long value from the column indicated by the specified index
 *
 * @param [in]	cursor		Navigates the result of the request for the select operation
 * @param [in]	column_index	The index of the destination column
 * @param [out]	data			The 64-bit integer value obtained from the column
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_sql_get_int64_data(resultset_cursor *cursor, int column_index, long long *data);

/**
 * @brief		Gets a double value from the column indicated by the specified index
 *
 * @param [in]	cursor		Navigates the result of the request for the select operation
 * @param [in]	column_index		The index of the destination column
 * @param [out]	data			The value obtained from the column as double
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_sql_get_double_data(resultset_cursor *cursor, int column_index, double *data);

/**
 * @brief		Gets a text value from the column indicated by the specified index
 *
 * @param [in]	cursor		Navigates the result of the request for the select operation
 * @param [in]	column_index	The index of the destination column
 * @param [out]	data			The value obtained from the column as text
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 */
EXPORT_API int datacontrol_sql_get_text_data(resultset_cursor *cursor, int column_index, char *data);

/**
 * @brief		Removes the @c cursor containing SQL result set
 *
 * @param [in]	cursor		A pointer to the result set cursor to be removed
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 */
EXPORT_API int datacontrol_sql_remove_cursor(resultset_cursor *cursor);

#ifdef __cplusplus
}
#endif

#endif /* _APPFW_DATA_CONTROL_SQL_ENUMERATOR_H_ */

