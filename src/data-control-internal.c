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
