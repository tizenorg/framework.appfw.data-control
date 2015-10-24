#include <dlog.h>
#include <errno.h>
#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pthread.h>

#include <appsvc/appsvc.h>
#include <aul/aul.h>
#include <bundle.h>
#include <pkgmgr-info.h>
#include <security-server.h>

#include "data-control-map.h"
#include "data-control-internal.h"

struct datacontrol_s {
	char *provider_id;
	char *data_id;
};

typedef struct
{
    char *provider_id;
    char *app_id;
    char *data_id;
    char *access_info;
    void *user_data;
    datacontrol_map_response_cb *map_response_cb;
} map_response_cb_s;

static void *datacontrol_map_tree_root = NULL;
static const int MAX_ARGUMENT_SIZE = 16384; // 16KB

static void
datacontrol_map_call_cb(const char *provider_id, int request_id, datacontrol_request_type type,
	const char *data_id, bool provider_result, const char *error, char **result_value_list, int result_value_count, void* data)
{
	LOGI("datacontrol_map_call_cb, dataID: %s", data_id);

	datacontrol_map_response_cb *callback = NULL;

	map_response_cb_s *map_dc = NULL;
	map_dc = (map_response_cb_s *)data;
	callback = map_dc->map_response_cb;
	if (!callback)
	{
		LOGE("no listener set");
		return;
	}

	datacontrol_h provider;
	datacontrol_map_create(&provider);

	datacontrol_map_set_provider_id(provider, provider_id);
	datacontrol_map_set_data_id(provider, data_id);

	switch (type)
	{
		case DATACONTROL_TYPE_MAP_GET:
		{
			LOGI("GET VALUE");
			if (callback != NULL && callback->get != NULL)
			{
				callback->get(request_id, provider, result_value_list, result_value_count, provider_result, error, map_dc->user_data);
			}
			else
			{
				LOGI("No registered callback function");
			}

			break;
		}
		case DATACONTROL_TYPE_MAP_SET:
		{
			LOGI("SET VALUE");
			if (callback != NULL && callback->set != NULL)
			{
				callback->set(request_id, provider, provider_result, error, map_dc->user_data);
			}
			else
			{
				LOGI("No registered callback function");
			}

			break;
		}
		case DATACONTROL_TYPE_MAP_ADD:
		{
			LOGI("ADD VALUE");
			if (callback != NULL && callback->add!= NULL)
			{
				callback->add(request_id, provider, provider_result, error, map_dc->user_data);
			}
			else
			{
				LOGI("No registered callback function");
			}

			break;
		}
		case DATACONTROL_TYPE_MAP_REMOVE:
		{
			LOGI("REMOVE VALUE");
			if (callback != NULL && callback->remove != NULL)
			{
				callback->remove(request_id, provider, provider_result, error, map_dc->user_data);
			}
			else
			{
				LOGI("No registered callback function");
			}
			break;
		}
		default:
			break;
	}

	datacontrol_map_destroy(provider);
}

static void
datacontrol_map_instance_free(void *datacontrol_map_instance)
{
	map_response_cb_s *dc = (map_response_cb_s *)datacontrol_map_instance;
	if (dc)
	{
		free(dc->provider_id);
		free(dc->data_id);
		free(dc->app_id);
		free(dc->access_info);
		free(datacontrol_map_instance);
	}

	return;
}

static int
datacontrol_map_instance_compare(const void *l_datacontrol_map_instance, const void *r_datacontrol_map_instance)
{
	map_response_cb_s *dc_left = (map_response_cb_s *)l_datacontrol_map_instance;
	map_response_cb_s *dc_right = (map_response_cb_s *)r_datacontrol_map_instance;
	return strcmp(dc_left->provider_id, dc_right->provider_id);
}

static char**
datacontrol_map_get_value_list(const char *path, int count)
{
	char **value_list = NULL;
	int i = 0;
	int fd = 0;
	int ret = 0;

	value_list = (char **) calloc(count, sizeof(char *));
	if (value_list == NULL)
	{
		LOGE("Failed to create value list");
		return NULL;
	}

	SECURE_LOGI("The result file of GET: %s", path);
	ret = security_server_shared_file_reopen(path, &fd);
	if (ret != SECURITY_SERVER_API_SUCCESS)
	{
		SECURE_LOGE("Opening the file(%s) is failed : %d", path, ret);
		goto ERROR;
	}

	while (count)
	{
		int length = 0;
		int size = read(fd, &length, sizeof(int));
		if (size <= 0)
		{
			SECURE_LOGE("unable to read the result value file: %d", errno);
			goto ERROR;
		}
		if (length > MAX_ARGUMENT_SIZE || length < 0)
		{
			SECURE_LOGE("Invalid length: %d", length);
			goto ERROR;
		}

		value_list[i] = (char *) calloc(length + 1, sizeof(char));

		size = read(fd, value_list[i], length);
		if (size <= 0)
		{
			SECURE_LOGE("unable to read the result value file: %d", errno);
			++i;
			goto ERROR;
		}

		LOGI("value_list[%d] = %s", i, value_list[i]);
		++i;
		--count;
	}

	close(fd);
	ret = security_server_shared_file_delete(path);
	if (ret != SECURITY_SERVER_API_SUCCESS)
	{
		SECURE_LOGE("unable to remove the result value file(%s): %d", path, ret);
	}

	return value_list;

ERROR:
	if (value_list)
	{
		int j;
		for (j = 0; j < i; j++)
		{
			free(value_list[j]);
		}
		free(value_list);
	}

	close(fd);
	ret = security_server_shared_file_delete(path);
	if (ret != SECURITY_SERVER_API_SUCCESS)
	{
		SECURE_LOGE("unable to remove the result value file(%s): %d", path, ret);
	}
	return NULL;
}

static int
datacontrol_map_handle_cb(bundle* b, int request_code, appsvc_result_val res, void* data)
{
	LOGI("datacontrol_map_handle_cb, request_code: %d, result: %d", request_code, res);

	int ret = 0;
	const char** result_list = NULL;
	const char* provider_id = NULL;
	const char* data_id = NULL;
	const char* error_message = NULL;
	datacontrol_request_type request_type = 0;
	int request_id = -1;
	int result_list_len = 0;
	int provider_result = 0;
	int value_count = 0;
	const char* result_path = NULL;
	char** value_list = NULL;
	const char* p = NULL;

	if (!b)
	{
		LOGE("the bundle returned from datacontrol-provider-service is null");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	p = appsvc_get_data(b, OSP_K_REQUEST_ID);
	if (!p)
	{
		LOGE("Invalid Bundle: request_id is null");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}
	else
	{
		request_id = atoi(p);
	}

	SECURE_LOGI("Request ID: %d", request_id);

	// result list
	result_list = appsvc_get_data_array(b, OSP_K_ARG, &result_list_len);
	if (!result_list)
	{
		LOGE("Invalid Bundle: arguement list is null");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	p = result_list[0]; // result list[0] = provider_result
	if (!p)
	{
		LOGE("Invalid Bundle: provider_result is null");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	LOGI("Provider result: %s", p);

	provider_result = atoi(p);

	error_message = result_list[1]; // result list[1] = error
	if (!error_message)
	{
		LOGE("Invalid Bundle: error_message is null");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	LOGI("Error message: %s", error_message);

	p = appsvc_get_data(b, OSP_K_DATACONTROL_REQUEST_TYPE);
	if (!p)
	{
		LOGE("Invalid Bundle: data-control request type is null");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	request_type = (datacontrol_request_type)atoi(p);

	provider_id = appsvc_get_data(b, OSP_K_DATACONTROL_PROVIDER);
	if (!provider_id)
	{
		LOGE("Invalid Bundle: provider_id is null");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	data_id = appsvc_get_data(b, OSP_K_DATACONTROL_DATA);
	if (!data_id)
	{
		LOGE("Invalid Bundle: data_id is null");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	SECURE_LOGI("Provider ID: %s, Data ID: %s, Operation type: %d", provider_id, data_id, request_type);

	switch (request_type)
	{
		case DATACONTROL_TYPE_MAP_GET:
		{
			LOGI("GET RESPONSE");
			if (provider_result)
			{
				value_count = atoi(result_list[2]);
				result_path = result_list[3];
				if (!result_path)
				{
					LOGE("map query result path is null");
					return DATACONTROL_ERROR_INVALID_PARAMETER;
				}
				value_list = datacontrol_map_get_value_list(result_path, value_count);
			}
			break;
		}
		case DATACONTROL_TYPE_MAP_SET:
		case DATACONTROL_TYPE_MAP_ADD:
		case DATACONTROL_TYPE_MAP_REMOVE:
		{
			LOGI("SET or ADD or REMOVE RESPONSE");
			break;
		}

		default:
			break;
	}

	if (request_type >= DATACONTROL_TYPE_MAP_GET && request_type <= DATACONTROL_TYPE_MAP_REMOVE)
	{
		datacontrol_map_call_cb(provider_id, request_id, request_type, data_id, provider_result, error_message, value_list, value_count, data);
		ret = DATACONTROL_ERROR_NONE;
	}
	else
	{
		ret = DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	return ret;
}

static void
app_svc_res_cb_map(bundle* b, int request_code, appsvc_result_val res, void* data)
{
	LOGI("app_svc_res_cb_map, request_code: %d, result: %d", request_code, res);

	if (data)
	{
		datacontrol_map_handle_cb(b, request_code, res, data);
	}
	else
	{
		LOGE("error: listener information is null");
	}
}


static int
datacontrol_map_request_provider(datacontrol_h provider, datacontrol_request_type type, bundle *arg_list, int request_id)
{
	SECURE_LOGI("Map Data control request, type: %d, request id: %d", type, request_id);

	char *app_id = NULL;
	void *data = NULL;

	if (type < DATACONTROL_TYPE_MAP_GET || type > DATACONTROL_TYPE_MAP_REMOVE)
	{
		LOGE("Invalid request type: %d", (int)type);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	if (!datacontrol_map_tree_root)
	{
		LOGE("The listener tree is empty");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	map_response_cb_s *map_dc_temp = (map_response_cb_s *)calloc(sizeof(map_response_cb_s),1);
	if (!map_dc_temp)
	{
		LOGE("Failed to create map datacontrol");
		return DATACONTROL_ERROR_OUT_OF_MEMORY;
	}

	map_dc_temp->provider_id = strdup(provider->provider_id);
	if (!map_dc_temp->provider_id)
	{
		LOGE("Failed to assign provider id to map data control: %d", errno);
		free(map_dc_temp);
		return DATACONTROL_ERROR_OUT_OF_MEMORY;
	}

	map_dc_temp->data_id = strdup(provider->data_id);
	if (!map_dc_temp->data_id)
	{
		LOGE("Failed to assign data id to map data control: %d", errno);
		free(map_dc_temp->provider_id);
		free(map_dc_temp);
		return DATACONTROL_ERROR_OUT_OF_MEMORY;
	}

	map_dc_temp->app_id = NULL;
	map_dc_temp->access_info = NULL;
	map_dc_temp->user_data = NULL;
	map_dc_temp->map_response_cb = NULL;

	void *map_dc_returned = NULL;
	map_dc_returned = tfind(map_dc_temp, &datacontrol_map_tree_root, datacontrol_map_instance_compare);

	datacontrol_map_instance_free(map_dc_temp);

	if (!map_dc_returned)
	{
		LOGE("Finding the map datacontrol in the listener tree is failed.");
		return DATACONTROL_ERROR_IO_ERROR;
	}

	map_response_cb_s *map_dc = *(map_response_cb_s **)map_dc_returned;
	app_id = map_dc->app_id;
	data = map_dc;

	SECURE_LOGI("Map datacontrol appid: %s", map_dc->app_id);

	char caller_app_id[255];
	pid_t pid = getpid();
	if (aul_app_get_appid_bypid(pid, caller_app_id, sizeof(caller_app_id)) != 0)
	{
		SECURE_LOGE("Failed to get appid by pid(%d).", pid);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	appsvc_set_operation(arg_list, APPSVC_OPERATION_DEFAULT);
	appsvc_set_appid(arg_list, app_id);
	bundle_add_str(arg_list, OSP_K_CALLER_TYPE, OSP_V_CALLER_TYPE_OSP);
	bundle_add_str(arg_list, OSP_K_LAUNCH_TYPE, OSP_V_LAUNCH_TYPE_DATACONTROL);
	bundle_add_str(arg_list, OSP_K_DATACONTROL_PROTOCOL_VERSION, OSP_V_VERSION_2_1_0_3);
	bundle_add_str(arg_list, AUL_K_CALLER_APPID, caller_app_id);
	bundle_add_str(arg_list, AUL_K_NO_CANCEL, "1");

	char datacontrol_request_operation[MAX_LEN_DATACONTROL_REQ_TYPE] = {0, };
	snprintf(datacontrol_request_operation, MAX_LEN_DATACONTROL_REQ_TYPE, "%d", (int)(type));
	bundle_add_str(arg_list, OSP_K_DATACONTROL_REQUEST_TYPE, datacontrol_request_operation);

	char req_id[32] = {0, };
	snprintf(req_id, 32, "%d", request_id);
	bundle_add_str(arg_list, OSP_K_REQUEST_ID, req_id);

	// For DataControl CAPI
	bundle_add_str(arg_list, AUL_K_DATA_CONTROL_TYPE, "CORE");

	SECURE_LOGI("Map data control request - provider id: %s, data id: %s, provider appid: %s, request ID: %s", provider->provider_id, provider->data_id, app_id, req_id);

	pid = -1;
	int count = 0;
	const int TRY_COUNT = 4;
	const struct timespec TRY_SLEEP_TIME = { 0, 1000 * 1000 * 1000 };

	do
	{
		pid = appsvc_run_service(arg_list, request_id, app_svc_res_cb_map, data);
		if (pid >= 0)
		{
			SECURE_LOGI("Launch the provider app successfully: %d", pid);
			return DATACONTROL_ERROR_NONE;
		}
		else if (pid == APPSVC_RET_EINVAL)
		{
			SECURE_LOGE("not able to launch service: %d", pid);
			return DATACONTROL_ERROR_INVALID_PARAMETER;
		}

		count++;

		nanosleep(&TRY_SLEEP_TIME, 0);
	}
	while (count < TRY_COUNT);

	SECURE_LOGE("unable to launch service: %d", pid);
	return DATACONTROL_ERROR_IO_ERROR;
}

int
datacontrol_map_create(datacontrol_h *provider)
{
	struct datacontrol_s *request;

	if (provider == NULL)
	{
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	request = malloc(sizeof(struct datacontrol_s));
	if (request == NULL)
	{
		return DATACONTROL_ERROR_OUT_OF_MEMORY;
	}

	request->provider_id = NULL;
	request->data_id = NULL;

	*provider = request;

	return 0;
}

int
datacontrol_map_destroy(datacontrol_h provider)
{
	if (provider == NULL)
	{
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	if (provider->provider_id != NULL)
	{
		free(provider->provider_id);
	}

	if (provider->data_id != NULL)
	{
		free(provider->data_id);
	}

	free(provider);

	return 0;
}

int
datacontrol_map_set_provider_id(datacontrol_h provider, const char *provider_id)
{
	if (provider == NULL || provider_id == NULL)
	{
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	if (provider->provider_id != NULL)
	{
		free(provider->provider_id);
	}

	provider->provider_id = strdup(provider_id);
	if (provider->provider_id == NULL)
	{
		return DATACONTROL_ERROR_OUT_OF_MEMORY;
	}

	return 0;
}

int
datacontrol_map_get_provider_id(datacontrol_h provider, char **provider_id)
{
	if (provider == NULL || provider_id == NULL)
	{
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	if (provider->provider_id != NULL)
	{
		*provider_id = strdup(provider->provider_id);
		if (*provider_id == NULL)
		{
			return DATACONTROL_ERROR_OUT_OF_MEMORY;
		}
	}
	else
	{
		*provider_id = NULL;
	}

	return 0;
}

int
datacontrol_map_set_data_id(datacontrol_h provider, const char *data_id)
{
	if (provider == NULL || data_id == NULL)
	{
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	if (provider->data_id != NULL)
	{
		free(provider->data_id);
	}

	provider->data_id = strdup(data_id);
	if (provider->data_id == NULL)
	{
		return DATACONTROL_ERROR_OUT_OF_MEMORY;
	}

	return 0;
}

int
datacontrol_map_get_data_id(datacontrol_h provider, char **data_id)
{
	if (provider == NULL || data_id == NULL)
	{
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	if (provider->data_id != NULL)
	{
		*data_id = strdup(provider->data_id);
		if (*data_id == NULL)
		{
			return DATACONTROL_ERROR_OUT_OF_MEMORY;
		}
	}
	else
	{
		*data_id = NULL;
	}
	return 0;
}

int
datacontrol_map_register_response_cb(datacontrol_h provider, datacontrol_map_response_cb* callback, void *user_data)
{
	int ret = 0;
	char* app_id = NULL;
	char* access = NULL;

	ret = pkgmgrinfo_appinfo_get_datacontrol_info(provider->provider_id, "Map", &app_id, &access);
	if (ret != PMINFO_R_OK)
	{
		LOGE("unable to get map data control information: %d", ret);
		return DATACONTROL_ERROR_IO_ERROR;
	}

	SECURE_LOGI("data control provider appid = %s", app_id);

	map_response_cb_s *map_dc_temp = (map_response_cb_s *)calloc(sizeof(map_response_cb_s), 1);
	if (!map_dc_temp)
	{
		LOGE("unable to create a temporary map data control");
		ret = DATACONTROL_ERROR_OUT_OF_MEMORY;
		goto EXCEPTION;
	}

	map_dc_temp->provider_id = strdup(provider->provider_id);
	if (!map_dc_temp->provider_id)
	{
		LOGE("unable to assign provider_id to map data control: %d", errno);
		ret = DATACONTROL_ERROR_OUT_OF_MEMORY;
		goto EXCEPTION;
	}

	map_dc_temp->data_id = strdup(provider->data_id);
	if (!map_dc_temp->data_id)
	{
		LOGE("unable to assign data_id to map data control: %d", errno);
		ret = DATACONTROL_ERROR_OUT_OF_MEMORY;
		goto EXCEPTION;
	}

	map_dc_temp->app_id = app_id;
	map_dc_temp->access_info = access;
	map_dc_temp->user_data = user_data;
	map_dc_temp->map_response_cb = callback;

	void *map_dc_returned = NULL;
	map_dc_returned = tsearch(map_dc_temp, &datacontrol_map_tree_root, datacontrol_map_instance_compare);

	map_response_cb_s *map_dc = *(map_response_cb_s **)map_dc_returned;
	if (map_dc != map_dc_temp)
	{
		map_dc->map_response_cb = callback;
		map_dc->user_data = user_data;
		LOGI("the data control is already set");
		datacontrol_map_instance_free(map_dc_temp);
	}

	return DATACONTROL_ERROR_NONE;

EXCEPTION:
	if (access)
		free(access);
	if (app_id)
		free(app_id);
	if (map_dc_temp)
	{
		if (map_dc_temp->provider_id)
			free(map_dc_temp->provider_id);
		if (map_dc_temp->data_id)
			free(map_dc_temp->data_id);
		free(map_dc_temp);
	}

	return ret;
}

int
datacontrol_map_unregister_response_cb(datacontrol_h provider)
{
	int ret = DATACONTROL_ERROR_NONE;
	map_response_cb_s *map_dc_temp = (map_response_cb_s *)calloc(sizeof(map_response_cb_s),1);


	if (!map_dc_temp)
	{
		LOGE("unable to create a temporary map data control");
		ret = DATACONTROL_ERROR_OUT_OF_MEMORY;
		goto EXCEPTION;
	}

	map_dc_temp->provider_id = strdup(provider->provider_id);
	if (!map_dc_temp->provider_id)
	{
		LOGE("unable to assign provider_id to map data control: %d", errno);
		ret = DATACONTROL_ERROR_OUT_OF_MEMORY;
		goto EXCEPTION;
	}

	void *map_dc_returned = NULL;

	map_dc_returned = tdelete(map_dc_temp, &datacontrol_map_tree_root, datacontrol_map_instance_compare);
	if (map_dc_returned == NULL)
	{
		LOGE("invalid parameter");
		ret = DATACONTROL_ERROR_INVALID_PARAMETER;
		goto EXCEPTION;
	}


EXCEPTION:
	 if (map_dc_temp)
	 {
		if (map_dc_temp->provider_id)
			free(map_dc_temp->provider_id);
		free(map_dc_temp);
	 }

	 return ret;
}

int
datacontrol_map_get(datacontrol_h provider, const char *key, int *request_id)
{
	return datacontrol_map_get_with_page(provider, key, request_id, 1, 20);
}

int
datacontrol_map_get_with_page(datacontrol_h provider, const char *key, int *request_id, int page_number, int count_per_page)
{
	int ret = 0;
	char* access = NULL;
	char *provider_appid = NULL;

	if (provider == NULL || provider->provider_id == NULL || provider->data_id == NULL || key == NULL || page_number <= 0 || count_per_page <= 0)
	{
		LOGE("Invalid parameter");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	SECURE_LOGI("Gets the value list from provider_id: %s, data_id: %s", provider->provider_id, provider->data_id);

	ret = pkgmgrinfo_appinfo_get_datacontrol_info(provider->provider_id, "Map", &provider_appid, &access);
	if (ret != PMINFO_R_OK)
	{
		LOGE("unable to get sql data control information: %d", ret);
		return DATACONTROL_ERROR_IO_ERROR;
	}
	if (provider_appid)
		free(provider_appid);

	if (NULL != access && !strcmp(access, WRITE_ONLY)) {
		LOGE("Provider has given [%s] permission only", access);
		free(access);
		return DATACONTROL_ERROR_PERMISSION_DENIED;
	}
	if (access)
		free(access);

	long long arg_size = (strlen(provider->data_id) + strlen(key)) * sizeof(wchar_t);
	if (arg_size > MAX_ARGUMENT_SIZE)
	{
		LOGE("The size of sending argument (%lld) exceeds the maximum limit.", arg_size);
		return DATACONTROL_ERROR_MAX_EXCEEDED;
	}

	bundle *b = bundle_create();
	if (!b)
	{
		LOGE("unable to create bundle: %d", errno);
		return DATACONTROL_ERROR_IO_ERROR;
	}

	bundle_add_str(b, OSP_K_DATACONTROL_PROVIDER, provider->provider_id);
	bundle_add_str(b, OSP_K_DATACONTROL_DATA, provider->data_id);

	const char* arg_list[4];
	arg_list[0] = provider->data_id;
	arg_list[1] = key;

	char page_no_str[32] = {0, };
	ret = snprintf(page_no_str, 32, "%d", page_number);
	if (ret < 0)
	{
		LOGE("unable to convert page no to string: %d", errno);
		bundle_free(b);
		return DATACONTROL_ERROR_IO_ERROR;
	}

	char count_per_page_str[32] = {0, };
	ret = snprintf(count_per_page_str, 32, "%d", count_per_page);
	if (ret < 0)
	{
		LOGE("unable to convert count per page no to string: %d", errno);
		bundle_free(b);
		return DATACONTROL_ERROR_IO_ERROR;
	}

	arg_list[2] = page_no_str;
	arg_list[3] = count_per_page_str;

	bundle_add_str_array(b, OSP_K_ARG, arg_list, 4);

	// Set the request id
	int reqId = _datacontrol_create_request_id();
	*request_id = reqId;

	ret = datacontrol_map_request_provider(provider, DATACONTROL_TYPE_MAP_GET, b, reqId);
	bundle_free(b);

	return ret;
}

int
datacontrol_map_set(datacontrol_h provider, const char *key, const char *old_value, const char *new_value, int *request_id)
{
	int ret = 0;
	char *access = NULL;
	char *provider_appid = NULL;

	if (provider == NULL || provider->provider_id == NULL || provider->data_id == NULL || key == NULL || old_value == NULL || new_value == NULL)
	{
		LOGE("Invalid parameter");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	SECURE_LOGI("Sets the old value to new value in provider_id: %s, data_id: %s", provider->provider_id, provider->data_id);

	ret = pkgmgrinfo_appinfo_get_datacontrol_info(provider->provider_id, "Map", &provider_appid, &access);
	if (ret != PMINFO_R_OK)
	{
		LOGE("unable to get sql data control information: %d", ret);
		return DATACONTROL_ERROR_IO_ERROR;
	}
	if (provider_appid)
		free(provider_appid);

	if (NULL != access && !strcmp(access, READ_ONLY)) {
		LOGE("Provider has given [%s] permission only", access);
		free(access);
		return DATACONTROL_ERROR_PERMISSION_DENIED;
	}
	if (access)
		free(access);

	long long arg_size = (strlen(provider->data_id) + strlen(key) + strlen(old_value) + strlen(new_value)) * sizeof(wchar_t);
	if (arg_size > MAX_ARGUMENT_SIZE)
	{
		LOGE("The size of sending argument (%lld) exceeds the maximum limit.", arg_size);
		return DATACONTROL_ERROR_MAX_EXCEEDED;
	}

	bundle *b = bundle_create();
	if (!b)
	{
		LOGE("unable to create bundle: %d", errno);
		return DATACONTROL_ERROR_IO_ERROR;
	}

	bundle_add_str(b, OSP_K_DATACONTROL_PROVIDER, provider->provider_id);
	bundle_add_str(b, OSP_K_DATACONTROL_DATA, provider->data_id);

	const char* arg_list[4];
	arg_list[0] = provider->data_id;
	arg_list[1] = key;
	arg_list[2] = old_value;
	arg_list[3] = new_value;

	bundle_add_str_array(b, OSP_K_ARG, arg_list, 4);

	// Set the request id
	int reqId = _datacontrol_create_request_id();
	*request_id = reqId;

	ret = datacontrol_map_request_provider(provider, DATACONTROL_TYPE_MAP_SET, b, reqId);
	bundle_free(b);

	return ret;
}

int
datacontrol_map_add(datacontrol_h provider, const char *key, const char *value, int *request_id)
{
	int ret = 0;
	char* access = NULL;
	char *provider_appid = NULL;

	if (provider == NULL || provider->provider_id == NULL || provider->data_id == NULL || key == NULL || value == NULL)
	{
		LOGE("Invalid parameter");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	SECURE_LOGI("Adds the value in provider_id: %s, data_id: %s", provider->provider_id, provider->data_id);

	ret = pkgmgrinfo_appinfo_get_datacontrol_info(provider->provider_id, "Map", &provider_appid, &access);
	if (ret != PMINFO_R_OK)
	{
		LOGE("unable to get sql data control information: %d", ret);
		return DATACONTROL_ERROR_IO_ERROR;
	}
	if (provider_appid)
		free(provider_appid);

	if (NULL != access && !strcmp(access, READ_ONLY)) {
		LOGE("Provider has given [%s] permission only", access);
		free(access);
		return DATACONTROL_ERROR_PERMISSION_DENIED;
	}
	if (access)
		free(access);

	long long arg_size = (strlen(provider->data_id) + strlen(key) + strlen(value)) * sizeof(wchar_t);
	if (arg_size > MAX_ARGUMENT_SIZE)
	{
		LOGE("The size of sending argument (%lld) exceeds the maximum limit.", arg_size);
		return DATACONTROL_ERROR_MAX_EXCEEDED;
	}

	bundle *b = bundle_create();
	if (!b)
	{
		LOGE("unable to create bundle: %d", errno);
		return DATACONTROL_ERROR_IO_ERROR;
	}

	bundle_add_str(b, OSP_K_DATACONTROL_PROVIDER, provider->provider_id);
	bundle_add_str(b, OSP_K_DATACONTROL_DATA, provider->data_id);

	const char* arg_list[3];
	arg_list[0] = provider->data_id;
	arg_list[1] = key;
	arg_list[2] = value;

	bundle_add_str_array(b, OSP_K_ARG, arg_list, 3);

	// Set the request id
	int reqId = _datacontrol_create_request_id();
	*request_id = reqId;

	ret = datacontrol_map_request_provider(provider, DATACONTROL_TYPE_MAP_ADD, b, reqId);
	bundle_free(b);

	return ret;
}

int
datacontrol_map_remove(datacontrol_h provider, const char *key, const char *value, int *request_id)
{
	int ret = 0;
	char *access = NULL;
	char *provider_appid = NULL;

	if (provider == NULL || provider->provider_id == NULL || provider->data_id == NULL || key == NULL || value == NULL)
	{
		LOGE("Invalid parameter");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	SECURE_LOGI("Removes the value in provider_id: %s, data_id: %s", provider->provider_id, provider->data_id);

	ret = pkgmgrinfo_appinfo_get_datacontrol_info(provider->provider_id, "Map", &provider_appid, &access);
	if (ret != PMINFO_R_OK)
	{
		LOGE("unable to get sql data control information: %d", ret);
		return DATACONTROL_ERROR_IO_ERROR;
	}
	if (provider_appid)
		free(provider_appid);

	if (NULL != access && !strcmp(access, READ_ONLY)) {
		LOGE("Provider has given [%s] permission only", access);
		free(access);
		return DATACONTROL_ERROR_PERMISSION_DENIED;
	}
	if (access)
		free(access);

	long long arg_size = (strlen(provider->data_id) + strlen(key) + strlen(value)) * sizeof(wchar_t);
	if (arg_size > MAX_ARGUMENT_SIZE)
	{
		LOGE("The size of sending argument (%lld) exceeds the maximum limit.", arg_size);
		return DATACONTROL_ERROR_MAX_EXCEEDED;
	}

	bundle *b = bundle_create();
	if (!b)
	{
		LOGE("unable to create bundle: %d", errno);
		return DATACONTROL_ERROR_IO_ERROR;
	}

	bundle_add_str(b, OSP_K_DATACONTROL_PROVIDER, provider->provider_id);
	bundle_add_str(b, OSP_K_DATACONTROL_DATA, provider->data_id);

	const char* arg_list[3];
	arg_list[0] = provider->data_id;
	arg_list[1] = key;
	arg_list[2] = value;

	bundle_add_str_array(b, OSP_K_ARG, arg_list, 3);

	// Set the request id
	int reqId = _datacontrol_create_request_id();
	*request_id = reqId;

	ret = datacontrol_map_request_provider(provider, DATACONTROL_TYPE_MAP_REMOVE, b, reqId);
	bundle_free(b);

	return ret;
}
