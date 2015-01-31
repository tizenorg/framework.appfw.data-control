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
 * @file	data-control-provider.h
 * @brief	This is the header file for the data control provider.
 */

#ifndef _APPFW_DATA_CONTROL_PROVIDER_H_
#define _APPFW_DATA_CONTROL_PROVIDER_H_

#include <data-control-types.h>
#include <data-control-sql-cursor.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief		Called when the insert request is received from an application using SQL-friendly interface based data control.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]  	insert_data	The column-value pairs to insert @n
 *							If the value is a string, the value must be wrapped in single quotes, else it does not need to be wrapped in single quotes.
 * @param [in]  user_data   The user data passed from the register function
 */
typedef void (*datacontrol_provider_sql_insert_request_cb)(int request_id, datacontrol_h provider,
		bundle *insert_data, void *user_data);

/**
 * @brief		Called when the update request is received from an application using SQL-friendly interface based data control.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]  	update_data	The column-value pairs to update @n
 *							If the value is a string, the value must be wrapped in single quotes, else it does not need to be wrapped in single quotes.
 * @param [in]	where		A filter to select the desired rows to update. @n
 *							It is an SQL 'WHERE' clause excluding the 'WHERE' itself such as column1 = 'stringValue' and column2 = numericValue.
 * @param [in]  user_data   The user data passed from the register function
 */
typedef void (*datacontrol_provider_sql_update_request_cb)(int request_id, datacontrol_h provider,
		bundle *update_data, const char *where, void *user_data);

/**
 * @brief		Called when the delete request is received from an application using SQL-friendly interface based data control.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]	where		A filter to select the desired rows to delete. @n
 *							It is an SQL 'WHERE' clause excluding the 'WHERE' itself such as column1 = 'stringValue' and column2 = numericValue.
 * @param [in]  user_data   The user data passed from the register function
 */
typedef void (*datacontrol_provider_sql_delete_request_cb)(int request_id, datacontrol_h provider,
		const char *where, void *user_data);

/**
 * @brief		Called when the select request is received from an application using SQL-friendly interface based data control.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]  	column_list	The column list to query
 * @param [in]  	column_count	The total number of columns to be queried
 * @param [in]	where		A filter to select the desired rows. @n
 *							It is an SQL 'WHERE' clause excluding the 'WHERE' itself such as column1 = 'stringValue' and column2 = numericValue.
 * @param [in]	order		The sorting order of the rows to query. @n
 *							It is an SQL 'ORDER BY' clause excluding the 'ORDER BY' itself.
 * @param [in]  user_data   The user data passed from the register function
 */
typedef void (*datacontrol_provider_sql_select_request_cb)(int request_id, datacontrol_h provider,
		const char **column_list, int column_count, const char *where, const char *order, void *user_data);

/**
 * @brief		Called when the request for obtaining the value list is received from the key-value structured data control consumer.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]	key			The key of the value list to obtain
 * @param [in]  user_data   The user data passed from the register function
 */
typedef void (*datacontrol_provider_map_get_value_request_cb)(int request_id, datacontrol_h provider, const char *key, void *user_data);

/**
 * @brief		Called when the request for replacing the value is received from the key-value structured data control consumer.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]	key			The key of the value to replace
 * @param [in]	old_value		The value to replace
 * @param [in]	new_value	The new value that replaces the existing value
 * @param [in]  user_data   The user data passed from the register function
 */
typedef void (*datacontrol_provider_map_set_value_request_cb)(int request_id, datacontrol_h provider, const char *key,
		const char *old_value, const char *new_value, void *user_data);

/**
 * @brief		Called when the request for adding the value is received from the key-value structured data control consumer.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]	key			The key of the value to add
 * @param [in]	value		The value to add
 * @param [in]  user_data   The user data passed from the register function
 */
typedef void (*datacontrol_provider_map_add_value_request_cb)(int request_id, datacontrol_h provider, const char *key,
		const char *value, void *user_data);

/**
 * @brief		Called when the request for removing the value is received from the key-value structured data control consumer.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]	key			The key of the value to remove
 * @param [in]	value		The value to remove
 * @param [in]  user_data   The user data passed from the register function
 */
typedef void (*datacontrol_provider_map_remove_value_request_cb)(int request_id, datacontrol_h provider, const char *key,
		const char *value, void *user_data);

/**
 * @brief		The structure type to contain the set of callback functions for handling the request events
 *			of SQL-friendly interface based data control.
 * @see		datacontrol_provider_sql_select_request_cb()
 * @see		datacontrol_provider_sql_insert_request_cb()
 * @see		datacontrol_provider_sql_update_request_cb()
 * @see		datacontrol_provider_sql_delete_request_cb()
 */
typedef struct
{
	datacontrol_provider_sql_insert_request_cb insert;
	datacontrol_provider_sql_select_request_cb select;
	datacontrol_provider_sql_update_request_cb update;
	datacontrol_provider_sql_delete_request_cb delete;
} datacontrol_provider_sql_cb;

/**
 * @brief		The structure type to contain the set of callback functions for handling the request events
 *			from the key-value structured data control consumer.
 * @see		datacontrol_provider_map_get_value_request_cb()
 * @see		datacontrol_provider_map_set_value_request_cb()
 * @see		datacontrol_provider_map_add_value_request_cb()
 * @see		datacontrol_provider_map_remove_value_request_cb()
 */
typedef struct
{
	datacontrol_provider_map_get_value_request_cb get;
	datacontrol_provider_map_set_value_request_cb set;
	datacontrol_provider_map_add_value_request_cb add;
	datacontrol_provider_map_remove_value_request_cb remove;
} datacontrol_provider_map_cb;

/**
 * @brief		Registers a callback function for the sql data control request.
 *			The provider is notified when a data control request is received from the client applications.
 * @param [in]	callback	The callback function to be called when a data control request is received
 * @param [in]	user_data	The user data to be passed to the callback function
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_provider_sql_register_cb(datacontrol_provider_sql_cb *callback, void *user_data);

/**
 * @brief		Unregisters the callback functions.
 * @return	0 on success, otherwise a negative error value.
 */
EXPORT_API int datacontrol_provider_sql_unregister_cb(void);

/**
 * @brief		Registers a callback function for the map data control request.
 *			The provider is notified when a data control request is received from the client applications.
 * @param [in]	callback	The callback function to be called when a data control request is received
 * @param [in]  user_data   The user data to be passed to the callback function
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_provider_map_register_cb(datacontrol_provider_map_cb *callback, void *user_data);

/**
 * @brief		Unregisters the callback functions.
 * @return	0 on success, otherwise a negative error value.
 */
EXPORT_API int datacontrol_provider_map_unregister_cb(void);

/**
 * @brief		Gets the application ID which sends the data control request.
 * @param [in]	request_id	The request ID
 * @param [out]	appid		The application ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_provider_get_client_appid(int request_id, char **appid);

/**
 * @brief		Sends the success result and the result set of the select request to the client application.
 * @param [in]	request_id	The request ID
 * @param [in]	db_handle	The result db handle for the result set
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_provider_send_select_result(int request_id, void *db_handle);

/**
 * @brief		Sends the success result of the insert request and the last inserted row ID to the client application.
 * @param [in]	request_id	The request ID
 * @param [in]	row_id		The row ID of the database changed by the insert request
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_provider_send_insert_result(int request_id, long long row_id);

/**
 * @brief		Sends the success result of the update request the client application.
 * @param [in]	request_id	The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_provider_send_update_result(int request_id);

/**
 * @brief		Sends the success result of the delete request the client application.
 * @param [in]	request_id	The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_provider_send_delete_result(int request_id);

/**
 * @brief		Sends the provider error message to the client application.
 * @param [in]	request_id	The request ID
 * @param [in]	error			The provider-defined error message
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_provider_send_error(int request_id, const char *error);

/**
 * @brief		Sends the success result of the request for setting, adding and removing the key-value structured data the client application.
 * @param [in]	request_id	The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_provider_send_map_result(int request_id);

/**
 * @brief		Sends the success result of the request for getting the value list the client application.
 * @param [in]	request_id	The request ID
 * @param [in]	value_list		The result value list
 * @param [in]	value_count	The number of the values
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 */
EXPORT_API int datacontrol_provider_send_map_get_value_result(int request_id, char **value_list, int value_count);

#ifdef __cplusplus
}
#endif

#endif /* _APPFW_DATA_CONTROL_PROVIDER_H_ */

