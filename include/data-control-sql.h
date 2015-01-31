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
 * @file	data-control-sql.h
 * @brief	This is the header file for the SQL-friendly interface based data control.
 */

#ifndef _APPFW_DATA_CONTROL_SQL_H_
#define _APPFW_DATA_CONTROL_SQL_H_

#include <data-control-types.h>
#include <data-control-sql-cursor.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief		Called when response is received for insert operation from an application using the SQL-friendly interface based data control.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]	inserted_row_id	The inserted row ID set by the data control
 * @param [in]	provider_result	Set to true if the data control provider successfully processed. @n
 *								false otherwise.
 * @param [in]	error		The error message from the data control provider
 * @param [in]	user_data	The user data passed from the register function
 */
typedef void (*datacontrol_sql_insert_response_cb)(int request_id, datacontrol_h provider,
		long long inserted_row_id, bool provider_result, const char *error, void *user_data);

/**
 * @brief		Called when response is received for delete operation from an application using the SQL-friendly interface based data control.
 *
 * @param [in]	request_id	The request ID that identifies the data control
 * @param [in]	provider_result	Set to true if the data control provider successfully processed. @n
 *								false otherwise.
 * @param [in]	error		The error message from the data control provider
 * @param [in]	user_data	The user data passed from the register function
 */
typedef void (*datacontrol_sql_delete_response_cb)(int request_id, datacontrol_h provider,
		bool provider_result, const char *error, void *user_data);

/**
 * @brief		Called when response is received for select operation from an application using the SQL-friendly interface based data control.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]	enumerator	Navigates the result of data control select request
 * @param [in]	provider_result	Set to true if the data control provider successfully processed. @n
 *								false  otherwise.
 * @param [in]	error		The error message from the data control provider
 * @param [in]	user_data	The user data passed from the register function
 */
typedef void (*datacontrol_sql_select_response_cb)(int request_id, datacontrol_h provider,
		resultset_cursor *enumerator, bool provider_result, const char *error, void *user_data);

/**
 * @brief		Called when response is received for update operation from an application using the SQL-friendly interface based data control.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]	provider_result	Set to true if the data control provider successfully processed. @n
 *								false  otherwise.
 * @param [in]	error		The error message from the data control provider
 * @param [in]	user_data	The user data passed from the register function
 */
typedef void (*datacontrol_sql_update_response_cb)(int request_id, datacontrol_h provider,
		bool provider_result, const char *error, void *user_data);

/**
 * @brief		The structure type to contain the set of callback functions for handling the response events
 *			of SQL-friendly interface based data control.
 * @see		datacontrol_sql_select_response_cb()
 * @see		datacontrol_sql_insert_response_cb()
 * @see		datacontrol_sql_update_response_cb()
 * @see		datacontrol_sql_delete_response_cb()
 */
typedef struct
{
	datacontrol_sql_select_response_cb select;
	datacontrol_sql_insert_response_cb insert;
	datacontrol_sql_update_response_cb update;
	datacontrol_sql_delete_response_cb delete;
} datacontrol_sql_response_cb;

/**
 * @brief		Creates a provider handle.
 * @param [out]	provider	The provider handle
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_sql_destroy()
 *
 * The following example demonstrates how to use the %datacontrol_sql_create() method.
 *
 * @code
 *
 *	int main()
 *	{
 *		const char *provider_id = "http://tizen.org/datacontrol/provider/example";
 *		const char *data_id = "table";
 *		datacontrol_h provider;
 * 		int result = 0;
 *
 *		result = datacontrol_sql_create(&provider);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Creating data control provider is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		result = datacontrol_sql_set_provider_id(provider, provider_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Setting providerID is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		result = datacontrol_sql_set_data_id(provider, data_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Setting dataID is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		// Executes some operations
 *
 *		result = datacontrol_sql_destroy(provider);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Destorying data control provider is failed with error: %d", result);
 *		}
 *
 *		return result;
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_sql_create(datacontrol_h *provider);

/**
 * @brief		Destroys the provider handle and releases all its resources.
 * @param [in]	provider	The provider handle
 * @return		0 on success, otherwise a negative error value.
 * @remark	When operations of data control are finished, this function must be called to prevent memory leak.
 * @see datacontrol_sql_create()
 */
EXPORT_API int datacontrol_sql_destroy(datacontrol_h provider);

/**
 * @brief		Sets the Provider ID.
 * @param [in]	provider	The provider handle
 * @param [in]	provider_id	 The data control provider ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_sql_get_provider_id()
 */
EXPORT_API int datacontrol_sql_set_provider_id(datacontrol_h provider, const char *provider_id);

/**
 * @brief		Gets the Provider ID.
 * @param [in]	provider	The provider handle
 * @param [out]	provider_id	 The data control provider ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_sql_set_provider_id()
 */
EXPORT_API int datacontrol_sql_get_provider_id(datacontrol_h provider, char **provider_id);

/**
 * @brief		Sets the Data ID.
 * @param [in]	provider	The provider handle
 * @param [in]	data_id	A string for identifying a specific table to operate. @n
 *						The string consists of one or more components separated by a slash('/').
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_sql_get_data_id()
 */
EXPORT_API int datacontrol_sql_set_data_id(datacontrol_h provider, const char *data_id);

/**
 * @brief		Gets the Data ID.
 * @param [in]	provider	The provider handle
 * @param [out]	data_id	A string for identifying a specific table to operate. @n
 *						The string consists of one or more components separated by a slash('/').
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_sql_set_data_id()
 */
EXPORT_API int datacontrol_sql_get_data_id(datacontrol_h provider, char **data_id);

/**
 * @brief		Registers a callback function for the sql data control response. @n
 *				The application is notified when a data control response is received from the @c provider.
 * @param [in]	provider	The provider handle
 * @param [in]	callback	The callback function to be called when a response is received.
 * @param [in]	user_data	The user data to be passed to the callback function
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_sql_unregister_response_cb()
 */
EXPORT_API int datacontrol_sql_register_response_cb(datacontrol_h provider, datacontrol_sql_response_cb* callback, void *user_data);

/**
 * @brief		Unregisters the callback function in @c provider.
 * @param [in]	provider	The provider handle
 * @return		0 on success, otherwise a negative error value.
 */
EXPORT_API int datacontrol_sql_unregister_response_cb(datacontrol_h provider);

/**
 * @brief		Deletes rows of a table owned by the SQL-type data control provider
 *
 * @remarks		If the value is a string, the value must be wrapped in single quotes, else it does not need to be wrapped in single quotes.
 * @param [in]	provider	The provider handle
 * @param [in]	where	A filter to select the desired rows to delete. @n
 *						It is an SQL 'WHERE' clause excluding the 'WHERE' itself such as column1 = 'stringValue' and column2 = numericValue.
 * @param [out]	request_id	The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 *
 * The following example demonstrates how to use the %datacontrol_sql_delete() method.
 *
 * @code
 *
 *	void sql_delete_response_cb(int request_id, datacontrol_h provider, bool provider_result, const char *error) {
 *		if (provider_result) {
 *			LOGI("The delete operation is successful");
 *		}
 *		else {
 *			LOGI("The delete operation for the request %d is failed. error message: %s", request_id, error);
 *		}
 *	}
 *
 *	datacontrol_sql_response_cb sql_callback;
 *
 *	int main()
 *	{
 *		const char *where = "group = 'friend'";
 *		int result = 0;
 *		int req_id = 0;
 *
 *		sql_callback.delete = sql_delete_response_cb;
 *		result = datacontrol_sql_register_response_cb(provider, &sql_callback);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Registering the callback function is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		result = datacontrol_sql_delete(provider, where, &req_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Deleting is failed with error: %d", result);
 *		}
 *		else {
 *			LOGI("req_id is %d", req_id);
 *		}
 *
 *		return result;
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_sql_delete(datacontrol_h provider, const char *where, int *request_id);

/**
 * @brief		Inserts new rows in a table owned by the SQL-type data control provider
 *
 * @param [in]	provider	The provider handle
 * @param [in]	insert_data	The column-value pairs to insert. @n
 *							If the value is a string, the value must be wrapped in single quotes,
 *							else it does not need to be wrapped in single quotes.
 * @param [out]	request_id	The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #DATACONTROL_ERROR_MAX_EXCEEDED Too long argument
 *
 * The following example demonstrates how to use the %datacontrol_sql_insert() method.
 *
 * @code
 *
 *	void sql_insert_response_cb(int request_id, datacontrol_h provider, long long inserted_row_id, bool provider_result, const char *error) {
 *		if (provider_result) {
 *			LOGI("The insert operation is successful");
 *		}
 *		else {
 *			LOGI("The insert operation for the request %d is failed. error message: %s", request_id, error);
 *		}
 *	}
 *
 *	datacontrol_sql_response_cb sql_callback;
 *
 *	int main()
 *	{
 *		int result = 0;
 *		int req_id = 0;
 *		bundle *b = NULL;
 *
 *		sql_callback.insert = sql_insert_response_cb;
 *		result = datacontrol_sql_register_response_cb(provider, &sql_callback);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Registering the callback function is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		b = bundle_create();
 *		bundle_add_str(b, "WORD", "test");
 *		bundle_add_str(b, "WORD_DESC", "test description");
 *
 *		result = datacontrol_sql_insert(provider, b, &req_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Inserting is failed with error: %d", result);
 *		}
 *		else {
 *			LOGI("req_id is %d", req_id);
 *		}
 *
 *		bundle_free(b);
 *		return result;
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_sql_insert(datacontrol_h provider, const bundle* insert_data, int *request_id);

/**
 * @brief		Selects the specified columns to be queried
 *
 * @param [in]	provider	The provider handle
 * @param [in]	column_list		The column list to query
 * @param [in]	column_count		The total number of columns to be queried
 * @param [in]	where			A filter to select the desired rows. @n
 *								It is an SQL 'WHERE' clause excluding the 'WHERE' itself such as column1 = 'stringValue' and column2 = numericValue.
 * @param [in]	order			The sorting order of the rows to query. @n
 *								It is an SQL 'ORDER BY' clause excluding the 'ORDER BY' itself.
 * @param [out]	request_id		The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 *
 * The following example demonstrates how to use the %datacontrol_sql_select() method.
 *
 * @code
 *
 *	void sql_select_response_cb(int request_id, datacontrol_h provider, resultset_cursor *enumerator, bool provider_result, const char *error) {
 *		if (provider_result) {
 *			LOGI("The select operation is successful");
 *		}
 *		else {
 *			LOGI("The select operation for the request %d is failed. error message: %s", request_id, error);
 *		}
 *	}
 *
 *	datacontrol_sql_response_cb sql_callback;
 *
 *	int main()
 *	{
 *		int result = 0;
 *		int req_id = 0;
 *		char *column_list[2];
 *		column_list[0] = "WORD";
 *		column_list[1] = "WORD_DESC";
 *		const char *where = "WORD = 'test'";
 *		const char *order = "WORD ASC";
 *
 *		sql_callback.select = sql_select_response_cb;
 *		result = datacontrol_sql_register_response_cb(provider, &sql_callback);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Registering the callback function is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		result = datacontrol_sql_select(provider, column_list, 2, where, order, &req_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Selecting is failed with error: %d", result);
 *		}
 *		else {
 *			LOGI("req_id is %d", req_id);
 *		}
 *
 *		return result;
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_sql_select(datacontrol_h provider, char **column_list, int column_count, const char *where, const char *order, int *request_id);

/**
 * @brief		Selects the specified columns to be queried
 *
 * @param [in]	provider	The provider handle
 * @param [in]	column_list		The column list to query
 * @param [in]	column_count		The total number of columns to be queried
 * @param [in]	where			A filter to select the desired rows. @n
 *								It is an SQL 'WHERE' clause excluding the 'WHERE' itself such as column1 = 'stringValue' and column2 = numericValue.
 * @param [in]	order			The sorting order of the rows to query. @n
 *								It is an SQL 'ORDER BY' clause excluding the 'ORDER BY' itself.
 * @param [in]	page_number		The page number of the result set @n
 *								It starts from 1.
 * @param [in]	count_per_page		The desired maximum count of rows on a page
 * @param [out]	request_id			The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_sql_select()
 */
EXPORT_API int datacontrol_sql_select_with_page(datacontrol_h provider, char **column_list, int column_count, const char *where, const char *order, int page_number, int count_per_page, int *request_id);

/**
 * @brief		Updates values of a table owned by the SQL-type data control provider.
 *
 * @param [in]	provider	The provider handle
 * @param [in]	update_data		The column-value pairs to update. @n
 *								If the value is a string, the value must be wrapped in single quotes,
 *								else it does not need to be wrapped in single quotes.
 * @param [in]	where			A filter to select the desired rows to update. @n
 *								It is an SQL 'WHERE' clause excluding the 'WHERE' itself such as column1 = 'stringValue' and column2 = numericValue.
 * @param [out]	request_id		The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #DATACONTROL_ERROR_MAX_EXCEEDED Too long argument
 *
 * The following example demonstrates how to use the %datacontrol_sql_update() method.
 *
 * @code
 *
 *	void sql_update_response_cb(int request_id, datacontrol_h provider, bool provider_result, const char *error) {
 *		if (provider_result) {
 *			LOGI("The update operation is successful");
 *		}
 *		else {
 *			LOGI("The update operation for the request %d is failed. error message: %s", request_id, error);
 *		}
 *	}
 *
 *	datacontrol_sql_response_cb sql_callback;
 *
 *	int main()
 *	{
 *		int result = 0;
 *		int req_id = 0;
 *		const char *where = "WORD = 'test'";
 *		bundle *b = NULL;
 *
 *		sql_callback.update = sql_update_response_cb;
 *		result = datacontrol_sql_register_response_cb(provider, &sql_callback);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Registering the callback function is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		b = bundle_create();
 *		bundle_add_str(b, "WORD", "test_new");
 *
 *		result = datacontrol_sql_update(provider, b, where, &req_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			LOGE("Updating is failed with error: %d", result);
 *		}
 *		else {
 *			LOGI("req_id is %d", req_id);
 *		}
 *
 *		bundle_free(b);
 *		return result;
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_sql_update(datacontrol_h provider, const bundle* update_data, const char *where, int *request_id);

#ifdef __cplusplus
}
#endif

#endif /* _APPFW_DATA_CONTROL_SQL_H_ */

