#include <dlog.h>
#include <errno.h>
#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pthread.h>
#include <sqlite3.h>
#include <limits.h>

#include <appsvc/appsvc.h>
#include <aul/aul.h>
#include <bundle.h>
#include <pkgmgr-info.h>
#include <security-server.h>

#include "data-control-sql.h"
#include "data-control-provider.h"
#include "data-control-internal.h"

#define ROW_ID_SIZE		32
#define RESULT_PATH_MAX		512


#define RESULT_PAGE_NUMBER		"RESULT_PAGE_NUMBER"
#define MAX_COUNT_PER_PAGE		"MAX_COUNT_PER_PAGE"
#define RESULT_VALUE_COUNT			"RESULT_VALUE_COUNT"

#define PACKET_INDEX_REQUEST_RESULT	0
#define PACKET_INDEX_ERROR_MSG		1
#define PACKET_INDEX_SELECT_RESULT_FILE	2
#define PACKET_INDEX_ROW_ID			2
#define PACKET_INDEX_VALUE_COUNT		2
#define PACKET_INDEX_GET_RESULT_FILE	3

#define PACKET_INDEX_DATAID	0
#define PACKET_INDEX_COLUMNCOUNT	1
#define PACKET_INDEX_MAP	2

#define PACKET_INDEX_UPDATEWHERE	3
#define PACKET_INDEX_DELETEWHERE	1

#define PACKET_INDEX_MAP_KEY	1
#define PACKET_INDEX_MAP_VALUE_1ST	2
#define PACKET_INDEX_MAP_VALUE_2ND	3
#define PACKET_INDEX_MAP_PAGE_NO	2
#define PACKET_INDEX_MAP_COUNT_PER_PAGE	3

static const int MAX_ARGUMENT_SIZE = 16384; // 16KB
static GHashTable *request_table = NULL;

//static pthread_mutex_t provider_lock = PTHREAD_MUTEX_INITIALIZER;

struct datacontrol_s {
	char *provider_id;
	char *data_id;
};


typedef int (*provider_handler_cb) (bundle * b, int request_id, void *data);

static datacontrol_provider_sql_cb* provider_sql_cb = NULL;
static datacontrol_provider_map_cb* provider_map_cb = NULL;
static void* provider_map_user_data = NULL;
static void* provider_sql_user_data = NULL;

static void
__free_data(gpointer data)
{
	if (data)
	{
		free(data);
		data = NULL;
	}
}

static void
__initialize_provider(void)
{
	request_table = g_hash_table_new_full(g_int_hash, g_int_equal, __free_data, __free_data);
}

static int
__provider_new_request_id(void)
{
	static int id = 0;

	g_atomic_int_inc(&id);

	return id;
}

static char*
__get_client_pkgid(bundle *b)
{
	const char *caller_appid = NULL;
	char *caller_pkgid = NULL;
	pkgmgrinfo_appinfo_h app_info_handle = NULL;

	caller_appid = bundle_get_val(b, AUL_K_CALLER_APPID);
	pkgmgrinfo_appinfo_get_appinfo(caller_appid, &app_info_handle);
	pkgmgrinfo_appinfo_get_pkgname(app_info_handle, &caller_pkgid);
	SECURE_LOGI("client pkg id : %s", caller_pkgid);

	return caller_pkgid ? strdup(caller_pkgid) : NULL;
}

static bundle*
__get_data_map(const char *path, int column_count)
{
	bundle* b = bundle_create();

	int len = 0;
	int i = 0;
	ssize_t size = 0;
	char *key = NULL;
	char *value = NULL;
	int fd = 0;
	int ret = 0;

	SECURE_LOGI("The request file of INSERT/UPDATE: %s", path);
	ret = security_server_shared_file_reopen(path, &fd);
	if (ret != SECURITY_SERVER_API_SUCCESS)
	{
		SECURE_LOGE("Opening the file(%s) is failed : %d", path, ret);
		return b;
	}

	for (i = 0; i < column_count; i++)
	{
		size = read(fd, &len, sizeof(int));
		if ((unsigned int)size < sizeof(int) || len < 0 || len > MAX_ARGUMENT_SIZE)
		{
			SECURE_LOGE("key length:%d, read():%s, returned:%d", len, strerror(errno), size);
			break;
		}

		key = calloc(len + 1, sizeof(char));
		if (key == NULL) {
			SECURE_LOGE("out of memory");
			break;
		}

		size = read(fd, key, len);	// key
		if (size < 0)
		{
			SECURE_LOGE("key length:%d, read():%s, returned:%d", len, strerror(errno), size);
			free(key);
			break;
		}

		size = read(fd, &len, sizeof(int));
		if ((unsigned int)size < sizeof(int) || len < 0 || len > MAX_ARGUMENT_SIZE)
		{
			SECURE_LOGE("value length:%d, read():%s, returned:%d", len, strerror(errno), size);
			free(key);
			break;
		}

		value = calloc(len + 1, sizeof(char));
		if (value == NULL) {
			SECURE_LOGE("out of memory");
			free(key);
			break;
		}

		size = read(fd, value, len); // value
		if (size < 0)
		{
			SECURE_LOGE("value length:%d, read():%s, returned:%d", len, strerror(errno), size);
			free(key);
			free(value);
			break;
		}

		LOGI("key: %s, value: %s", key, value);

		bundle_add_str(b, key, value);

		free(key);
		free(value);
	}

	fsync(fd);
	close(fd);
	ret = security_server_shared_file_delete(path);
	if (ret != SECURITY_SERVER_API_SUCCESS)
	{
		SECURE_LOGE("unable to remove the request file of INSERT/UPDATE(%s): %d", path, ret);
	}

	return b;
}

static int
__set_select_result(bundle* b, const char* path, void* data)
{
	LOGI("__set_select_result");
	// The provider application should call the sqlite3_open().
	// and it also should call the sqlite3_prepare_v2() in datacontrol_provider_sql_select_request_cb().
	// and then, it should call the datacontrol_provider_send_select_result() with a pointer to sqlite3_stmt.
	// The 3rd param 'data' is the pointer to sqlite3_stmt.

	// In this function, the result set is written in specified file path as specific form.
	// [sizeof(int)] row count
	// [sizeof(int)] column count
	// [sieeof(int)] total size of column names
	// [sizeof(int)] column type x N
	// [  variant  ] column name x N
	// [sizeof(int)] type
	// [sizeof(int)] size
	// [  varient  ] content

	int column_count = 0;
	int i = 0;
	char *column_name = NULL;
	int total_len_of_column_names = 0;
	int count_per_page = 0;
	int page_number = 1;
	int offset = 0;
	int offset_idx = 0;
	int row_count = 0;
	sqlite3_stmt *state = (sqlite3_stmt *)data;
	int ret = 0;
	int fd = 0;
	char *client_pkgid = NULL;

	if (b ==NULL || path == NULL || data == NULL)
	{
		LOGE("The input param is invalid.");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	if (sqlite3_reset(state) != SQLITE_OK)
	{
		LOGE("sqlite3_reset() is failed.");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	if (sqlite3_step(state) != SQLITE_ROW)
	{
		LOGE("The DB does not have another row.");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	client_pkgid = __get_client_pkgid(b);
	ret = security_server_shared_file_open(path, client_pkgid, &fd);
	if (ret == SECURITY_SERVER_API_ERROR_FILE_EXIST) {
		SECURE_LOGE("The file(%s) already exist, delete and retry to open", path);
		int ret_temp = security_server_shared_file_delete(path);
		if (ret_temp != SECURITY_SERVER_API_SUCCESS) {
			SECURE_LOGE("Delete the file(%s) is failed : %d", path, ret_temp);
		} else {
			ret = security_server_shared_file_open(path, client_pkgid, &fd);
		}
	}

	if (ret != SECURITY_SERVER_API_SUCCESS)
	{
		SECURE_LOGE("Opening the file(%s) is failed : %d", path, ret);
		free(client_pkgid);
		return DATACONTROL_ERROR_IO_ERROR;
	}
	free(client_pkgid);

	// 1. column count
	column_count = sqlite3_column_count(state);
	if (lseek(fd, sizeof(int), SEEK_SET) == -1)
	{
		LOGE("lseek is failed. errno =  %d", errno);
	}
	if (write(fd, &column_count, sizeof(int)) == -1)
	{
		LOGE("Writing a column_count to a file descriptor is failed. errno = %d", errno);
	}

	// 2. column type x column_count
	// #define SQLITE_INTEGER	1
	// #define SQLITE_FLOAT	2
	// #define SQLITE_TEXT	3
	// #define SQLITE_BLOB	4
	// #define SQLITE_NULL	5
	if (lseek(fd, sizeof(int), SEEK_CUR) == -1)
	{
		LOGE("lseek is failed. errno =  %d", errno);
	}

	for (i = 0; i < column_count; ++i)
	{
		int type = sqlite3_column_type(state, i);
		if (write(fd, &type, sizeof(int)) == -1)
		{
			LOGE("Writing a type to a file descriptor is failed. errno = %d", errno);
		}
	}

	// 3. column name x column_count
	for (i = 0; i < column_count; i++)
	{
		column_name = (char *)sqlite3_column_name(state, i);
		if (column_name == NULL) {
			LOGE("sqlite3_column_name is failed. errno = %d", errno);
		} else {
			column_name = strcat(column_name, "\n");
			if (write(fd, column_name, strlen(column_name)) == -1)
			{
				LOGE("Writing a column_name to a file descriptor is failed. errno = %d", errno);
			}
			total_len_of_column_names += strlen(column_name);
		}
	}

	// 4. total length of column names
	if (lseek(fd, sizeof(int) * 2, SEEK_SET) == -1)
	{
		LOGE("lseek is failed. errno =  %d", errno);
	}
	if (write(fd, &total_len_of_column_names, sizeof(int)) == -1)
	{
		LOGE("Writing a total_len_of_column_names to a file descriptor is failed. errno = %d", errno);
	}
	// 5. type, size and value of each element
	if (lseek(fd, (sizeof(int) * column_count) + total_len_of_column_names, SEEK_CUR) == -1)
	{
		LOGE("lseek is failed. errno =  %d", errno);
	}

	page_number = atoi(bundle_get_val(b, RESULT_PAGE_NUMBER));
	count_per_page = atoi(bundle_get_val(b, MAX_COUNT_PER_PAGE));
	offset = (page_number - 1) * count_per_page;

	LOGI("page_number: %d, count_per_page: %d, offset: %d", page_number, count_per_page, offset);
	do
	{

		offset_idx ++;
		if (offset_idx > offset) {

			for (i = 0; i < column_count; ++i)
			{
				int type = 0;
				int size = 0;
				void* value = NULL;
				bool is_null_type = false;
				int column_type = sqlite3_column_type(state, i);
				long long tmp_long = 0;
				double tmp_double = 0.0;
				switch (column_type)
				{
					case SQLITE_INTEGER:
						{
							type = 1;
							size = sizeof(long long);
							tmp_long = sqlite3_column_int64(state, i);
							value = &tmp_long;
							break;
						}
					case SQLITE_FLOAT:
						{
							type = 2;
							size = sizeof(double);
							tmp_double = sqlite3_column_double(state, i);
							value =&tmp_double;
							break;
						}
					case SQLITE_TEXT:
						{
							type = 3;
							value = (char *)sqlite3_column_text(state, i);
							size = strlen(value);
							break;
						}
					case SQLITE_BLOB:
						{
							type = 4;
							size = sqlite3_column_bytes(state, i);
							value = (char *)sqlite3_column_blob(state, i);
							break;
						}
					case SQLITE_NULL:
						{
							type = 5;
							size = 0;
							is_null_type = true;
							break;
						}
					default:
						{
							LOGE("The column type is invalid.");
							break;
						}
				}

				if (write(fd, &type, sizeof(int)) == -1)
				{
					LOGE("Writing a type to a file descriptor is failed. errno = %d", errno);
				}
				if (write(fd, &size, sizeof(int)) == -1)
				{
					LOGE("Writing a size to a file descriptor is failed. errno = %d", errno);
				}
				if (size > 0 && size < INT_MAX && !is_null_type)
				{
					if (write(fd, value, size) == -1)
					{
						LOGE("Writing a value to a file descriptor is failed. errno = %d", errno);
					}
				}
			}
			++row_count;
		}

	} while(sqlite3_step(state) == SQLITE_ROW && row_count < count_per_page);

	// 6. row count
	if (lseek(fd, 0, SEEK_SET) == -1)
	{
		LOGE("lseek is failed. errno =  %d", errno);
	}
	if (write(fd, &row_count, sizeof(int)) == -1)
	{
		LOGE("Writing a row_count to a file descriptor is failed. errno = %d", errno);
	}
	close(fd);


	return DATACONTROL_ERROR_NONE;
}

static int
__set_get_value_result(bundle *b, const char* path, char **value_list)
{
	int i = 0;
	int fd = -1;
	int ret = -1;
	char *client_pkgid = NULL;

	if (b == NULL || path == NULL || value_list == NULL)
	{
		LOGE("The input param is invalid.");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	int page_number = atoi(bundle_get_val(b, RESULT_PAGE_NUMBER));
	int count_per_page = atoi(bundle_get_val(b, MAX_COUNT_PER_PAGE));
	int value_count = atoi(bundle_get_val(b, RESULT_VALUE_COUNT));
	int current_offset = (page_number - 1) * count_per_page;
	int remain_count = value_count - current_offset;
	remain_count = (remain_count > 0) ? remain_count : 0;	// round off to zero if the negative num is found
	int add_value_count = (count_per_page > remain_count) ? remain_count : count_per_page;

	if (add_value_count < value_count)
	{
		bundle_del(b, RESULT_VALUE_COUNT);
		char value_count_str[32] = {0,};
		snprintf(value_count_str, 32, "%d", add_value_count);
		bundle_add_str(b, RESULT_VALUE_COUNT, value_count_str);
	}

	if (add_value_count <= 0)
	{
		LOGI("There is no value list.");
		return DATACONTROL_ERROR_NONE;
	}

	client_pkgid = __get_client_pkgid(b);
	ret = security_server_shared_file_open(path, client_pkgid, &fd);
	if (ret == SECURITY_SERVER_API_ERROR_FILE_EXIST) {
		SECURE_LOGE("The file(%s) already exist, delete and retry to open", path);
		int ret_temp = security_server_shared_file_delete(path);
		if (ret_temp != SECURITY_SERVER_API_SUCCESS) {
			SECURE_LOGE("Delete the file(%s) is failed : %d", path, ret_temp);
		} else {
			ret = security_server_shared_file_open(path, client_pkgid, &fd);
		}
	}

	if (ret != SECURITY_SERVER_API_SUCCESS)
	{
		SECURE_LOGE("Opening the file(%s) is failed : %d", path, ret);
		free(client_pkgid);
		return DATACONTROL_ERROR_IO_ERROR;
	}
	free(client_pkgid);

	for (i = 0; i < add_value_count; ++i)
	{
		int length = strlen(value_list[current_offset + i]);
		if (write(fd, &length, sizeof(int)) == -1)
		{
			LOGE("Writing a length to a file descriptor is failed. errno = %d", errno);
		}
		if (write(fd, value_list[current_offset + i], length) == -1)
		{
			LOGE("Writing a value_list to a file descriptor is failed. errno = %d", errno);
		}
	}

	fsync(fd);
	close(fd);
	return DATACONTROL_ERROR_NONE;
}

static char*
__get_result_file_path(bundle *b)
{
	LOGI("__get_result_file_path");
	const char *caller = bundle_get_val(b, AUL_K_CALLER_APPID);
	if (!caller)
	{
		LOGE("caller appid is NULL.");
		return NULL;
	}

	const char *caller_req_id = bundle_get_val(b, OSP_K_REQUEST_ID);

	char *result_path = calloc(RESULT_PATH_MAX, sizeof(char));

	if (!result_path)
	{
		LOGE("result path is NULL.");
		return NULL;
	}
	snprintf(result_path, RESULT_PATH_MAX, "%s%s%s", DATACONTROL_RESULT_FILE_PREFIX, caller, caller_req_id);

	SECURE_LOGI("result file path: %s", result_path);

	return result_path;
}

static bundle*
__set_result(bundle* b, datacontrol_request_type type, void* data)
{
	bundle* res;
	aul_create_result_bundle(b, &res);

	// Set the type
	char type_str[MAX_LEN_DATACONTROL_REQ_TYPE + 1] = {0,};
	if (type == DATACONTROL_TYPE_UNDEFINED || type == DATACONTROL_TYPE_ERROR)
	{
		char *request_type = (char*)bundle_get_val(b, OSP_K_DATACONTROL_REQUEST_TYPE);
		strncpy(type_str, request_type, MAX_LEN_DATACONTROL_REQ_TYPE);
		LOGI("type is %s", type_str);
	}
	else
	{
		snprintf(type_str, MAX_LEN_DATACONTROL_REQ_TYPE, "%d", (int)type);
	}
	bundle_add_str(res, OSP_K_DATACONTROL_REQUEST_TYPE, type_str);

	// Set the provider id
	char *provider_id = (char*)bundle_get_val(b, OSP_K_DATACONTROL_PROVIDER);
	bundle_add_str(res, OSP_K_DATACONTROL_PROVIDER, provider_id);

	// Set the data id
	char *data_id = (char*)bundle_get_val(b, OSP_K_DATACONTROL_DATA);
	bundle_add_str(res, OSP_K_DATACONTROL_DATA, data_id);

	// Set the caller request id
	char *request_id = (char*)bundle_get_val(b, OSP_K_REQUEST_ID);
	bundle_add_str(res, OSP_K_REQUEST_ID, request_id);

	switch(type)
	{
		case DATACONTROL_TYPE_SQL_SELECT:
		{
			const char* list[3];

			list[PACKET_INDEX_REQUEST_RESULT] = "1";		// request result
			list[PACKET_INDEX_ERROR_MSG] = DATACONTROL_EMPTY;

			char *path = __get_result_file_path(b);
			if (path != NULL)
			{
				int ret = __set_select_result(b, path, data);
				if (ret < 0)
				{
					memset(path, 0, RESULT_PATH_MAX);
					strcpy(path, "NoResultSet");
					LOGI("Empty ResultSet");
				}
				list[PACKET_INDEX_SELECT_RESULT_FILE] = path;
			}
			else
			{
				list[PACKET_INDEX_SELECT_RESULT_FILE] = DATACONTROL_EMPTY;
			}

			bundle_add_str_array(res, OSP_K_ARG, list, 3);

			if (path != NULL)
			{
				free(path);
			}

			break;
		}

		case DATACONTROL_TYPE_SQL_INSERT:
		{
			long long row_id = *(long long*)data;

			const char* list[3];
			list[PACKET_INDEX_REQUEST_RESULT] = "1";		// request result
			list[PACKET_INDEX_ERROR_MSG] = DATACONTROL_EMPTY;

			// Set the row value
			char row_str[ROW_ID_SIZE] = {0,};
			snprintf(row_str, ROW_ID_SIZE, "%lld", row_id);

			list[PACKET_INDEX_ROW_ID] = row_str;

			bundle_add_str_array(res, OSP_K_ARG, list, 3);
			break;
		}
		case DATACONTROL_TYPE_SQL_UPDATE:
		case DATACONTROL_TYPE_SQL_DELETE:
		{
			const char* list[2];
			list[PACKET_INDEX_REQUEST_RESULT] = "1";		// request result
			list[PACKET_INDEX_ERROR_MSG] = DATACONTROL_EMPTY;

			bundle_add_str_array(res, OSP_K_ARG, list, 2);
			break;
		}
		case DATACONTROL_TYPE_MAP_GET:
		{
			const char* list[4];

			list[PACKET_INDEX_REQUEST_RESULT] = "1";		// request result
			list[PACKET_INDEX_ERROR_MSG] = DATACONTROL_EMPTY;

			char *path = __get_result_file_path(b);
			if (path != NULL)
			{
				char **value_list = (char **)data;
				__set_get_value_result(b, path, value_list);
				list[PACKET_INDEX_VALUE_COUNT] = bundle_get_val(b, RESULT_VALUE_COUNT);	// value count
				list[PACKET_INDEX_GET_RESULT_FILE] = path;
			}
			else
			{
				list[PACKET_INDEX_VALUE_COUNT] = 0;	// value count
				list[PACKET_INDEX_GET_RESULT_FILE] = DATACONTROL_EMPTY;
			}

			bundle_add_str_array(res, OSP_K_ARG, list, 4);

			if (path != NULL)
			{
				free(path);
			}

			break;
		}
		case DATACONTROL_TYPE_UNDEFINED:	// DATACONTROL_TYPE_MAP_SET || ADD || REMOVE
		{
			const char* list[2];
			list[PACKET_INDEX_REQUEST_RESULT] = "1";		// request result
			list[PACKET_INDEX_ERROR_MSG] = DATACONTROL_EMPTY;

			bundle_add_str_array(res, OSP_K_ARG, list, 2);
			break;
		}
		default:  // Error
		{
			const char* list[2];
			list[PACKET_INDEX_REQUEST_RESULT] = "0";		// request result
			list[PACKET_INDEX_ERROR_MSG] = (char*)data;  // error string

			bundle_add_str_array(res, OSP_K_ARG, list, 2);
			break;
		}
	}

	return res;
}

static int
__send_result(bundle* b, datacontrol_request_type type)
{
	int ret = aul_send_service_result(b);

	if (ret < 0)
	{
		LOGE("Fail to send a result to caller");

		int index = 0;

		switch (type)
		{
			case DATACONTROL_TYPE_SQL_SELECT:
			{
				index = PACKET_INDEX_SELECT_RESULT_FILE;
				break;
			}
			case DATACONTROL_TYPE_MAP_GET:
			{
				index = PACKET_INDEX_GET_RESULT_FILE;
				break;
			}
			default:
			{
				bundle_free(b);
				return DATACONTROL_ERROR_IO_ERROR;
			}
		}

		int len = 0;
		const char **str_arr = bundle_get_str_array(b, OSP_K_ARG, &len);
		SECURE_LOGI("result file: %s (%d)", str_arr[index], index);
		ret = security_server_shared_file_delete(str_arr[index]);
		if (ret != SECURITY_SERVER_API_SUCCESS)
		{
			SECURE_LOGE("unable to remove the result file: %d", ret);
		}

		bundle_free(b);
		return DATACONTROL_ERROR_IO_ERROR;
	}

	bundle_free(b);
	return DATACONTROL_ERROR_NONE;
}

int
__datacontrol_handler_cb(bundle *b, int request_id, void* data)
{
	LOGI("datacontrol_handler_cb");

	const char *request_type = bundle_get_val(b, OSP_K_DATACONTROL_REQUEST_TYPE);
	if (request_type == NULL)
	{
		LOGE("Invalid data control request");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	// Get the request type
	datacontrol_request_type type = atoi(request_type);
	if (type >= DATACONTROL_TYPE_SQL_SELECT && type <= DATACONTROL_TYPE_SQL_DELETE)
	{
		if (provider_sql_cb == NULL)
		{
			LOGE("SQL callback is not registered.");
			return DATACONTROL_ERROR_INVALID_PARAMETER;
		}
	}
	else if (type >= DATACONTROL_TYPE_MAP_GET && type <= DATACONTROL_TYPE_MAP_REMOVE)
	{
		if (provider_map_cb == NULL)
		{
			LOGE("Map callback is not registered.");
			return DATACONTROL_ERROR_INVALID_PARAMETER;
		}
	}
	else
	{
		LOGE("Invalid requeste type");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	int len = 0;
	const char **arg_list = bundle_get_str_array(b, OSP_K_ARG, &len);

	datacontrol_h provider = malloc(sizeof(struct datacontrol_s));
	if (provider == NULL) {
		LOGE("Fail to alloc provider");
		return DATACONTROL_ERROR_OUT_OF_MEMORY;
	}

	// Set the provider ID
	provider->provider_id = (char*)bundle_get_val(b, OSP_K_DATACONTROL_PROVIDER);

	// Set the data ID
	provider->data_id = (char*)arg_list[PACKET_INDEX_DATAID];

	// Set the request ID
	int provider_req_id = __provider_new_request_id();

	SECURE_LOGI("Provider ID: %s, data ID: %s, request type: %s", provider->provider_id, provider->data_id, request_type);

	// Add the data to the table
	int *key = malloc(sizeof(int));
	if (key == NULL) {
		free(provider);
		LOGE("Fail to alloc key");
		return DATACONTROL_ERROR_OUT_OF_MEMORY;
	}
	*key = provider_req_id;

	bundle *value = bundle_dup(b);
	g_hash_table_insert(request_table, key, value);

	switch (type)
	{
		case DATACONTROL_TYPE_SQL_SELECT:
			{
				int i = 1;
				int current = 0;
				int column_count = atoi(arg_list[i++]); // Column count

				LOGI("SELECT column count: %d", column_count);

				const char** column_list = (const char**)malloc(column_count * (sizeof(char *)));
				if (column_list == NULL) {
					free(provider);
					LOGE("Fail to alloc column_list");
					return DATACONTROL_ERROR_OUT_OF_MEMORY;
				}

				while (current < column_count)
				{
					column_list[current++] = arg_list[i++];  // Column data

					LOGI("Column %d: %s", current, column_list[current-1]);
				}

				const char *where = arg_list[i++];  // where
				const char *order = arg_list[i++];  // order

				LOGI("where: %s, order: %s", where, order);

				if (strncmp(where, DATACONTROL_EMPTY, strlen(DATACONTROL_EMPTY)) == 0)
				{
					where = NULL;
				}

				if (strncmp(order, DATACONTROL_EMPTY, strlen(DATACONTROL_EMPTY)) == 0)
				{
					order = NULL;
				}

				const char *page_number = arg_list[i++];
				const char *per_page =  arg_list[i];

				bundle_add_str(value, RESULT_PAGE_NUMBER, page_number);
				bundle_add_str(value, MAX_COUNT_PER_PAGE, per_page);

				provider_sql_cb->select(provider_req_id, provider, column_list, column_count, where, order, provider_sql_user_data);

				free(column_list);

				break;
			}
		case DATACONTROL_TYPE_SQL_INSERT:
		case DATACONTROL_TYPE_SQL_UPDATE:
			{
				int column_count = atoi(arg_list[PACKET_INDEX_COLUMNCOUNT]);
				const char *map_path = arg_list[PACKET_INDEX_MAP];

				LOGI("INSERT / UPDATE handler");
				SECURE_LOGI("Data path: %s, Column count: %d", map_path, column_count);

				bundle* map = __get_data_map(map_path, column_count);

				if (type == DATACONTROL_TYPE_SQL_INSERT)
				{
					SECURE_LOGI("INSERT column count: %d, map_path: %s", column_count, map_path);
					provider_sql_cb->insert(provider_req_id, provider, map, provider_sql_user_data);
				}
				else
				{
					const char *where = arg_list[PACKET_INDEX_UPDATEWHERE];
					LOGI("UPDATE from where: %s", where);

					if (strncmp(where, DATACONTROL_EMPTY, strlen(DATACONTROL_EMPTY)) == 0)
					{
						where = NULL;
					}
					provider_sql_cb->update(provider_req_id, provider, map, where, provider_sql_user_data);
				}

				bundle_free(map);
				break;
			}
		case DATACONTROL_TYPE_SQL_DELETE:
			{
				const char *where = arg_list[PACKET_INDEX_DELETEWHERE];

				LOGI("DELETE from where: %s", where);
				if (strncmp(where, DATACONTROL_EMPTY, strlen(DATACONTROL_EMPTY)) == 0)
				{
					where = NULL;
				}
				provider_sql_cb->delete(provider_req_id, provider, where, provider_sql_user_data);
				break;
			}
		case DATACONTROL_TYPE_MAP_GET:
			{
				const char *map_key = arg_list[PACKET_INDEX_MAP_KEY];
				const char *page_number= arg_list[PACKET_INDEX_MAP_PAGE_NO];
				const char *count_per_page =  arg_list[PACKET_INDEX_MAP_COUNT_PER_PAGE];
				bundle_add_str(value, RESULT_PAGE_NUMBER, page_number);
				bundle_add_str(value, MAX_COUNT_PER_PAGE, count_per_page);

				LOGI("Gets the value list related with the key(%s) from Map datacontrol. ", map_key);

				provider_map_cb->get(provider_req_id, provider, map_key, provider_map_user_data);
				break;
			}
		case DATACONTROL_TYPE_MAP_SET:
			{
				const char *map_key = arg_list[PACKET_INDEX_MAP_KEY];
				const char *old_value = arg_list[PACKET_INDEX_MAP_VALUE_1ST];
				const char *new_value = arg_list[PACKET_INDEX_MAP_VALUE_2ND];

				LOGI("Sets the old value(%s) of the key(%s) to the new value(%s) in Map datacontrol.", old_value, map_key, new_value);

				provider_map_cb->set(provider_req_id, provider, map_key, old_value, new_value, provider_map_user_data);
				break;
			}
		case DATACONTROL_TYPE_MAP_ADD:
			{
				const char *map_key = arg_list[PACKET_INDEX_MAP_KEY];
				const char *map_value = arg_list[PACKET_INDEX_MAP_VALUE_1ST];

				LOGI("Adds the %s-%s in Map datacontrol.", map_key, map_value);

				provider_map_cb->add(provider_req_id, provider, map_key, map_value, provider_map_user_data);
				break;
			}
		case DATACONTROL_TYPE_MAP_REMOVE:
			{
				const char *map_key = arg_list[PACKET_INDEX_MAP_KEY];
				const char *map_value = arg_list[PACKET_INDEX_MAP_VALUE_1ST];

				LOGI("Removes the %s-%s in Map datacontrol.", map_key, map_value);

				provider_map_cb->remove(provider_req_id, provider, map_key, map_value, provider_map_user_data);
				break;
			}
		default:
				break;
	}

	free(provider);

	return DATACONTROL_ERROR_NONE;
}

int
datacontrol_provider_sql_register_cb(datacontrol_provider_sql_cb *callback, void *user_data)
{
	int ret = DATACONTROL_ERROR_NONE;

	if (callback == NULL)
	{
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	if (request_table == NULL)
	{
		__initialize_provider();
	}

	LOGI("datacontrol_provider_sql_register_cb");

	provider_sql_cb = callback;
	provider_sql_user_data = user_data;

	if (provider_map_cb == NULL)	// If the provider_map_cb was registered(not NULL), __datacontrol_handler_cb is set already.
	{
		ret = aul_set_data_control_provider_cb(__datacontrol_handler_cb);
	}

	return ret;
}

int
datacontrol_provider_sql_unregister_cb(void)
{
	if (provider_map_cb == NULL)	// When both SQL_cb and Map_cb are unregisted, unsetting the provider cb is possible.
	{
		aul_unset_data_control_provider_cb();
	}
	provider_sql_cb = NULL;
	provider_sql_user_data = NULL;

	return DATACONTROL_ERROR_NONE;
}

int datacontrol_provider_map_register_cb(datacontrol_provider_map_cb *callback, void *user_data)
{
	int ret = DATACONTROL_ERROR_NONE;

	if (callback == NULL)
	{
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	if (request_table == NULL)
	{
		__initialize_provider();
	}

	LOGI("datacontrol_provider_map_register_cb");

	provider_map_cb = callback;
	provider_map_user_data = user_data;

	if (provider_sql_cb == NULL)	// If the provider_sql_cb was registered(not NULL), __datacontrol_handler_cb is set already.
	{
		ret = aul_set_data_control_provider_cb(__datacontrol_handler_cb);
	}

	return ret;
}

int datacontrol_provider_map_unregister_cb(void)
{
	if (provider_sql_cb == NULL)	// When both SQL_cb and Map_cb are unregisted, unsetting the provider cb is possible.
	{
		aul_unset_data_control_provider_cb();
	}
	provider_map_cb = NULL;
	provider_map_user_data = NULL;

	return DATACONTROL_ERROR_NONE;
}

int
datacontrol_provider_get_client_appid(int request_id, char **appid)
{
	if (request_table == NULL)
	{
		__initialize_provider();
	}

	bundle* b = g_hash_table_lookup(request_table, &request_id);
	if (!b)
	{
		SECURE_LOGE("No data for the request id: %d", request_id);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	const char *caller = bundle_get_val(b, AUL_K_CALLER_APPID);
	if (!caller)
	{
		SECURE_LOGE("No appid for the request id: %d", request_id);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	SECURE_LOGI("Request ID: %d, caller appid: %s", request_id, caller);

	*appid = strdup(caller);

	return DATACONTROL_ERROR_NONE;
}

int
datacontrol_provider_send_select_result(int request_id, void *db_handle)
{
	SECURE_LOGI("Send a select result for request id: %d", request_id);

	if (request_table == NULL)
	{
		__initialize_provider();
	}

	bundle* b = g_hash_table_lookup(request_table, &request_id);
	if (!b)
	{
		SECURE_LOGE("No data for the request id: %d", request_id);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	bundle* res = __set_result(b, DATACONTROL_TYPE_SQL_SELECT, db_handle);

	return __send_result(res, DATACONTROL_TYPE_SQL_SELECT);
}

int
datacontrol_provider_send_insert_result(int request_id, long long row_id)
{
	SECURE_LOGI("Send an insert result for request id: %d", request_id);

	if (request_table == NULL)
	{
		__initialize_provider();
	}

	bundle* b = g_hash_table_lookup(request_table, &request_id);
	if (!b)
	{
		SECURE_LOGE("No data for the request id: %d", request_id);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	bundle* res = __set_result(b, DATACONTROL_TYPE_SQL_INSERT, (void*)&row_id);

	return __send_result(res, DATACONTROL_TYPE_SQL_INSERT);
}

int
datacontrol_provider_send_update_result(int request_id)
{
	SECURE_LOGI("Send an update result for request id: %d", request_id);

	if (request_table == NULL)
	{
		__initialize_provider();
	}

	bundle* b = g_hash_table_lookup(request_table, &request_id);
	if (!b)
	{
		SECURE_LOGE("No data for the request id: %d", request_id);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	bundle* res = __set_result(b, DATACONTROL_TYPE_SQL_UPDATE, NULL);

	return __send_result(res, DATACONTROL_TYPE_SQL_UPDATE);
}

int
datacontrol_provider_send_delete_result(int request_id)
{
	SECURE_LOGI("Send a delete result for request id: %d", request_id);

	if (request_table == NULL)
	{
		__initialize_provider();
	}

	bundle* b = g_hash_table_lookup(request_table, &request_id);
	if (!b)
	{
		SECURE_LOGE("No data for the request id: %d", request_id);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	bundle* res = __set_result(b, DATACONTROL_TYPE_SQL_DELETE, NULL);

	return __send_result(res, DATACONTROL_TYPE_SQL_DELETE);
}

int
datacontrol_provider_send_error(int request_id, const char *error)
{
	SECURE_LOGI("Send an error for request id: %d", request_id);

	if (request_table == NULL)
	{
		__initialize_provider();
	}

	bundle* b = g_hash_table_lookup(request_table, &request_id);
	if (!b)
	{
		SECURE_LOGE("No data for the request id: %d", request_id);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	bundle* res = __set_result(b, DATACONTROL_TYPE_ERROR, (void*)error);

	return __send_result(res, DATACONTROL_TYPE_ERROR);
}

int
datacontrol_provider_send_map_result(int request_id)
{
	SECURE_LOGI("Send a set/add/remove result for request id: %d", request_id);

	if (request_table == NULL)
	{
		__initialize_provider();
	}

	bundle* b = g_hash_table_lookup(request_table, &request_id);
	if (!b)
	{
		SECURE_LOGE("No data for the request id: %d", request_id);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	bundle* res = __set_result(b, DATACONTROL_TYPE_UNDEFINED, NULL);

	return __send_result(res, DATACONTROL_TYPE_UNDEFINED);
}

int
datacontrol_provider_send_map_get_value_result(int request_id, char **value_list, int value_count)
{
	SECURE_LOGI("Send a get result for request id: %d", request_id);

	if (request_table == NULL)
	{
		__initialize_provider();
	}

	bundle* b = g_hash_table_lookup(request_table, &request_id);
	if (!b)
	{
		SECURE_LOGE("No data for the request id: %d", request_id);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	char value_count_str[32] = {0,};
	snprintf(value_count_str, 32, "%d", value_count);
	bundle_add_str(b, RESULT_VALUE_COUNT, value_count_str);

	bundle* res = __set_result(b, DATACONTROL_TYPE_MAP_GET, value_list);

	return __send_result(res, DATACONTROL_TYPE_MAP_GET);
}
