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
 * @file	data-control-map.h
 * @brief	This is the header file for the key-value structured data control.
 */

#ifndef _APPFW_DATA_CONTROL_MAP_H_
#define _APPFW_DATA_CONTROL_MAP_H_

#include <data-control-types.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief		Called when the result value list is received from the key-value structured data control provider.
 *
 * @param [in]	request_id	The request ID
 * @param [in]	provider		The provider handle
 * @param [in]	result_value_list	The result value list of the data control request that gets the matching values
 * @param [in]	result_value_count	The number of the values
 * @param [in]	provider_result	Set to true if the data control provider successfully processed. @n
 *								false otherwise.
 * @param [in]	error		The error message from the data control provider
 * @param [in]	user_data	The user data passed from the register function
 */
typedef void (*datacontrol_map_get_response_cb)(int request_id, datacontrol_h provider,
		char ** result_value_list, int result_value_count, bool provider_result, const char *error, void *user_data);

/**
 * @brief		Called when the response is received from the key-value structured data control provider.
 *
 * @param [in]	request_id	The request ID that identifies the data control
 * @param [in]	provider		The provider handle
 * @param [in]	provider_result	Set to true if the data control provider successfully processed. @n
 *								false otherwise.
 * @param [in]	error		The error message from the data control provider
 * @param [in]	user_data	The user data passed from the register function
 */
typedef void (*datacontrol_map_set_response_cb)(int request_id, datacontrol_h provider,
		bool provider_result, const char *error, void *user_data);

/**
 * @brief		Called when the response is received from the key-value structured data control provider.
 *
 * @param [in]	request_id	The request ID that identifies the data control
 * @param [in]	provider		The provider handle
 * @param [in]	provider_result	Set to true if the data control provider successfully processed. @n
 *								false otherwise.
 * @param [in]	error		The error message from the data control provider
 * @param [in]	user_data	The user data passed from the register function
 */
typedef void (*datacontrol_map_add_response_cb)(int request_id, datacontrol_h provider,
		bool provider_result, const char *error, void *user_data);

/**
 * @brief		Called when the response is received from the key-value structured data control provider.
 *
 * @param [in]	request_id	The request ID that identifies the data control
 * @param [in]	provider		The provider handle
 * @param [in]	provider_result	Set to true if the data control provider successfully processed. @n
 *								false otherwise.
 * @param [in]	error		The error message from the data control provider
 * @param [in]	user_data	The user data passed from the register function
 */
typedef void (*datacontrol_map_remove_response_cb)(int request_id, datacontrol_h provider,
		bool provider_result, const char *error, void *user_data);

/**
 * @brief		The structure type to contain the set of callback functions for handling the response events
 *			of the key-value structured data control.
 * @see		datacontrol_map_get_response_cb()
 * @see		datacontrol_map_set_response_cb()
 * @see		datacontrol_map_add_response_cb()
 * @see		datacontrol_map_remove_response_cb()
 */
typedef struct
{
	datacontrol_map_get_response_cb get;
	datacontrol_map_set_response_cb set;
	datacontrol_map_add_response_cb add;
	datacontrol_map_remove_response_cb remove;
} datacontrol_map_response_cb;

/**
 * @brief		Creates a provider handle.
 * @param [out]	provider	The provider handle
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_map_destroy()
 *
 * The following example demonstrates how to use the %datacontrol_map_create() method.
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
 *		result = datacontrol_map_create(&provider);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Creating data control provider is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		result = datacontrol_map_set_provider_id(provider, provider_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Setting providerID is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		result = datacontrol_map_set_data_id(provider, data_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Setting dataID is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		// Executes some operations
 *
 *		result = datacontrol_map_destroy(provider);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Destorying data control provider is failed with error: %d", result);
 *		}
 *
 *		return result;
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_map_create(datacontrol_h *provider);

/**
 * @brief		Destroys the provider handle and releases all its resources.
 * @param [in]	provider	The provider handle
 * @return		0 on success, otherwise a negative error value.
 * @remark	When operations of data control are finished, this function must be called to prevent memory leak.
 * @see datacontrol_map_create()
 */
EXPORT_API int datacontrol_map_destroy(datacontrol_h provider);

/**
 * @brief		Sets the Provider ID.
 * @param [in]	provider	The provider handle
 * @param [in]	provider_id	 The data control provider ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_map_get_provider_id()
 */
EXPORT_API int datacontrol_map_set_provider_id(datacontrol_h provider, const char *provider_id);

/**
 * @brief		Gets the Provider ID.
 * @param [in]	provider	The provider handle
 * @param [out]	provider_id	 The data control provider ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_map_set_provider_id()
 */
EXPORT_API int datacontrol_map_get_provider_id(datacontrol_h provider, char **provider_id);

/**
 * @brief		Sets the Data ID.
 * @param [in]	provider	The provider handle
 * @param [in]	data_id	A string for identifying a specific table to operate. @n
 *						The string consists of one or more components separated by a slash('/').
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_map_get_data_id()
 */
EXPORT_API int datacontrol_map_set_data_id(datacontrol_h provider, const char *data_id);

/**
 * @brief		Gets the Data ID.
 * @param [in]	provider	The provider handle
 * @param [out]	data_id	A string for identifying a specific table to operate. @n
 *						The string consists of one or more components separated by a slash('/').
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_map_set_data_id()
 */
EXPORT_API int datacontrol_map_get_data_id(datacontrol_h provider, char **data_id);

/**
 * @brief		Registers a callback function for the key-value structured data control response. @n
 *				The application is notified when a data control response is received from the @c provider.
 * @param [in]	provider	The provider handle
 * @param [in]	callback	The callback function to be called when a response is received.
 * @param [in]	user_data	The user data to be passed to the callback function
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @see	datacontrol_map_unregister_response_cb()
 */
EXPORT_API int datacontrol_map_register_response_cb(datacontrol_h provider, datacontrol_map_response_cb* callback, void *user_data);

/**
 * @brief		Unregisters the callback function in @c provider.
 * @param [in]	provider	The provider handle
 * @return		0 on success, otherwise a negative error value.
 */
EXPORT_API int datacontrol_map_unregister_response_cb(datacontrol_h provider);

/**
 * @brief		Gets the value list associated with the specified @c key from the key-values map owned by the key-value structured data control provider.
 *
 * @param [in]	provider	The provider handle
 * @param [in]	key		The key of the value list to obtain
 * @param [out]	request_id	The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #DATACONTROL_ERROR_MAX_EXCEEDED Too long argument
 *
 * The following example demonstrates how to use the %datacontrol_map_get() method.
 *
 * @code
 *
 *	void map_get_response_cb(int request_id, datacontrol_h provider,
 *			char **result_value_list, int result_value_count, bool provider_result, const char *error)
 *	{
 *		if (provider_result) {
 *			dlog_print(DLOG_INFO, LOG_TAG, "The get operation is successful");
 *		}
 *		else {
 *			dlog_print(DLOG_INFO, LOG_TAG, "The get operation for the request %d is failed. error message: %s", request_id, error);
 *		}
 *	}
 *
 *	datacontrol_map_response_cb map_callback;
 *
 *	int main()
 *	{
 *		int result = 0;
 *		int req_id = 0;
 *		char *key = "key";
 *
 *		map_callback.get = map_get_response_cb;
 *		result = datacontrol_map_register_response_cb(provider, &map_callback);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Registering the callback function is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		result = datacontrol_map_get(provider, key, &req_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Getting the value list of the key(%s) is failed with error: %d", key, result);
 *		}
 *		else {
 *			dlog_print(DLOG_INFO, LOG_TAG, "req_id is %d", req_id);
 *		}
 *
 *		return result;
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_map_get(datacontrol_h provider, const char *key, int *request_id);

/**
 * @brief		Gets the value list associated with the specified @c key from the key-values map owned by the key-value structured data control provider.
 *
 * @param [in]	provider	The provider handle
 * @param [in]	key		The key of the value list to obtain
 * @param [out]	request_id	The request ID
 * @param [in]	page_number		The page number of the value set @n
 *								It starts from 1.
 * @param [in]	count_per_page	The desired maximum count of the data items per page
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #DATACONTROL_ERROR_MAX_EXCEEDED Too long argument
 */
EXPORT_API int datacontrol_map_get_with_page(datacontrol_h provider, const char *key, int *request_id, int page_number, int count_per_page);

/**
 * @brief		Sets the value associated with the specified @c key to a new value.
 *
 * @param [in]	provider	The provider handle
 * @param [in]	key		The key of the value to replace
 * @param [in]	old_value		The value to replace
 * @param [in]	new_value	The new value that replaces the existing value
 * @param [out]	request_id	The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #DATACONTROL_ERROR_MAX_EXCEEDED Too long argument
 *
 * The following example demonstrates how to use the %datacontrol_map_set() method.
 *
 * @code
 *
 *	void map_set_response_cb(int request_id, datacontrol_h provider, bool provider_result, const char *error)
 *	{
 *		if (provider_result) {
 *			dlog_print(DLOG_INFO, LOG_TAG, "The set operation is successful");
 *		}
 *		else {
 *			dlog_print(DLOG_INFO, LOG_TAG, "The set operation for the request %d is failed. error message: %s", request_id, error);
 *		}
 *	}
 *
 *	datacontrol_map_response_cb map_callback;
 *
 *	int main()
 *	{
 *		int result = 0;
 *		int req_id = 0;
 *		char *key = "key";
 *		char *old_value = "old value";
 *		char *new_value = "new value";
 *
 *		map_callback.set = map_set_response_cb;
 *		result = datacontrol_map_register_response_cb(provider, &map_callback);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Registering the callback function is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		result = datacontrol_map_set(provider, key, old_value, new_value, &req_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Replacing old_value(%s) with new_value(%s) is failed with error: %d", old_value, new_value, result);
 *		}
 *		else {
 *			dlog_print(DLOG_INFO, LOG_TAG, "req_id is %d", req_id);
 *		}
 *
 *		return result;
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_map_set(datacontrol_h provider, const char *key, const char *old_value, const char *new_value, int *request_id);

/**
 * @brief		Adds the @c value associated with the specified @c key to the key-values map owned by the key-value structured data control provider.
 *
 * @param [in]	provider	The provider handle
 * @param [in]	key		The key of the value to add
 * @param [in]	value		The value to add
 * @param [out]	request_id	The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #DATACONTROL_ERROR_MAX_EXCEEDED Too long argument
 *
 * The following example demonstrates how to use the %datacontrol_map_add() method.
 *
 * @code
 *
 *	void map_add_response_cb(int request_id, datacontrol_h provider, bool provider_result, const char *error) {
 *		if (provider_result) {
 *			dlog_print(DLOG_INFO, LOG_TAG, "The add operation is successful");
 *		}
 *		else {
 *			dlog_print(DLOG_INFO, LOG_TAG, "The add operation for the request %d is failed. error message: %s", request_id, error);
 *		}
 *	}
 *
 *	datacontrol_map_response_cb map_callback;
 *
 *	int main()
 *	{
 *		int result = 0;
 *		int req_id = 0;
 *		const char *key = "key";
 *		const char *value = "value";
 *
 *		map_callback.add = map_add_response_cb;
 *		result = datacontrol_map_register_response_cb(provider, &map_callback);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Registering the callback function is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		result = datacontrol_map_add(provider, key, value, &req_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Adding %s-%s pair is failed with error: %d", key, value, result);
 *		}
 *		else {
 *			dlog_print(DLOG_INFO, LOG_TAG, "req_id is %d", req_id);
 *		}
 *
 *		return result;
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_map_add(datacontrol_h provider, const char *key, const char *value, int *request_id);

/**
 * @brief		Removes the @c value associated with the specified @c key from the key-values map owned by the key-value structured data control provider.
 *
 * @param [in]	provider	The provider handle
 * @param [in]	key		The key of the value to remove
 * @param [in]	value		The value to remove
 * @param [out]	request_id	The request ID
 * @return		0 on success, otherwise a negative error value.
 * @retval #DATACONTROL_ERROR_NONE	Successful
 * @retval #DATACONTROL_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #DATACONTROL_ERROR_IO_ERROR I/O error
 * @retval #DATACONTROL_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #DATACONTROL_ERROR_MAX_EXCEEDED Too long argument
 *
 * The following example demonstrates how to use the %datacontrol_map_remove() method.
 *
 * @code
 *
 *	void map_remove_response_cb(int request_id, datacontrol_h provider, bool provider_result, const char *error) {
 *		if (provider_result) {
 *			dlog_print(DLOG_INFO, LOG_TAG, "The remove operation is successful");
 *		}
 *		else {
 *			dlog_print(DLOG_INFO, LOG_TAG, "The remove operation for the request %d is failed. error message: %s", request_id, error);
 *		}
 *	}
 *
 *	datacontrol_map_response_cb map_callback;
 *
 *	int main()
 *	{
 *		int result = 0;
 *		int req_id = 0;
 *		const char *key = "key";
 *		const char *value = "value";
 *
 *		...
 *
 *		map_callback.remove = map_remove_response_cb;
 *		result = datacontrol_map_register_response_cb(provider, &map_callback);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Registering the callback function is failed with error: %d", result);
 *			return result;
 *		}
 *
 *		result = datacontrol_map_remove(provider, key, value, &req_id);
 *		if (result != DATACONTROL_ERROR_NONE) {
 *			dlog_print(DLOG_ERROR, LOG_TAG, "Removing %s-%s pair is failed with error: %d", key, value, result);
 *		}
 *		else {
 *			dlog_print(DLOG_INFO, LOG_TAG, "req_id is %d", req_id);
 *		}
 *
 *		return result;
 *	}
 *
 * @endcode
 */
EXPORT_API int datacontrol_map_remove(datacontrol_h provider, const char *key, const char *value, int *request_id);

#ifdef __cplusplus
}
#endif

#endif /* _APPFW_DATA_CONTROL_MAP_H_ */

