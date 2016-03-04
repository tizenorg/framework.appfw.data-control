#include <dlog.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pthread.h>

#include <bundle.h>
#include <pkgmgr-info.h>
#include <security-server.h>

#include "data-control-sql-cursor.h"
#include "data-control-internal.h"

#define MAX_COLUMN_SIZE				512
#define MAX_STATEMENT_SIZE			1024
#define NATIVE_SMACK_POSTFIX			".native"
int
_datacontrol_sql_get_cursor(const char *path)
{

	return 0;
}

int
_datacontrol_create_request_id(void)
{
	static int id = 0;

	g_atomic_int_inc(&id);

	return id;
}

int _shared_file_open(const char *insert_map_file, char *pkgid, const char *appid, int *fd)
{
	pkgmgrinfo_pkginfo_h handle = NULL;
	pkgmgrinfo_appinfo_h appinfo_handle = NULL;
	char *smack_label = NULL;
	char *client_label = NULL;
	char *apptype = NULL;
	char *pkgtype = NULL;
	int client_label_len = 0;

	int ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret != PMINFO_R_OK) {
		LOGE("failed to get pkginfo\n");
		return PMINFO_R_ERROR;
	}
	ret = pkgmgrinfo_pkginfo_get_custom_smack_label(handle, &smack_label);
	if (ret != PMINFO_R_OK) {
		LOGE("failed to get custom smack_label\n");
		ret = PMINFO_R_ERROR;
		goto end;
	}
	if (smack_label == NULL)
		smack_label = pkgid;

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	if (ret != PMINFO_R_OK) {
		LOGE("failed to get pkgtype\n");
		ret = PMINFO_R_ERROR;
		goto end;
	}

	if (pkgmgrinfo_appinfo_get_appinfo(appid, &appinfo_handle) != PMINFO_R_OK) {
		LOGE("failed to get apptype\n");
		ret = PMINFO_R_ERROR;
		goto end;
	}
	ret = pkgmgrinfo_appinfo_get_apptype(appinfo_handle, &apptype);
	if (ret != PMINFO_R_OK) {
		LOGE("failed to get apptype\n");
		ret = PMINFO_R_ERROR;
		goto end;
	}

	if(strcmp(apptype, "webapp") != 0 && strcmp(pkgtype, "wgt") == 0) {
		client_label_len = strlen(smack_label) + strlen(NATIVE_SMACK_POSTFIX)  + 1;
		client_label = (char *)calloc(client_label_len, sizeof(char));
		snprintf(client_label, client_label_len, "%s%s", smack_label, NATIVE_SMACK_POSTFIX);
	} else {
		client_label = strdup(smack_label);
	}

	ret = security_server_shared_file_open(insert_map_file, client_label, fd);
	if (ret == SECURITY_SERVER_API_ERROR_FILE_EXIST) {
		LOGE("The file(%s) already exist, delete and retry to open", insert_map_file);
		int ret_temp = security_server_shared_file_delete(insert_map_file);
		if (ret_temp != SECURITY_SERVER_API_SUCCESS) {
			LOGE("Delete the file(%s) is failed : %d", insert_map_file, ret_temp);
		} else {
			ret = security_server_shared_file_open(insert_map_file, client_label, fd);
		}
	}
end:
	if (handle)
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	if (appinfo_handle)
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo_handle);
	free(client_label);

	return ret;
}

