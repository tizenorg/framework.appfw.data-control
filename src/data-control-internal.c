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

char*
_datacontrol_create_select_statement(char *data_id, const char **column_list, int column_count, const char *where, const char *order, int page_number, int count_per_page)
{
	char *column = calloc(MAX_COLUMN_SIZE, sizeof(char));
	int i = 0;

	while (i < column_count - 1)
	{
		LOGI("column i = %d, %s", i, column_list[i]);
		strcat(column, column_list[i]);
		strcat(column, ", ");
		i++;
	}

	LOGI("column i = %d, %s", i, column_list[i]);
	strcat(column, column_list[i]);

	char *statement = calloc(MAX_STATEMENT_SIZE, sizeof(char));
	snprintf(statement, MAX_STATEMENT_SIZE, "SELECT %s * FROM %s WHERE %s ORDER BY %s", column, data_id, where, order);

	LOGI("SQL statement: %s", statement);

	free(column);
	return statement;
}

int
_datacontrol_create_request_id(void)
{
	static int id = 0;

	g_atomic_int_inc(&id);

	return id;
}
