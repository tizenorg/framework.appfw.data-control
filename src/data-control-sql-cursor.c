#include <dlog.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <security-server.h>

#include "data-control-sql-cursor.h"

#undef LOG_TAG
#ifndef LOG_TAG
#define LOG_TAG "DATA_CONTROL"
#endif

#define MAX_ROW_COUNT	        1024

static int *row_offset_list = NULL;

resultset_cursor* datacontrol_sql_get_cursor(const char * path)
{
	int ret = 0;
	resultset_cursor *cursor = (resultset_cursor *)calloc(sizeof(resultset_cursor), 1);
	if (!cursor)
	{
		LOGE("unable to create cursor");
		return NULL;
	}

	cursor->resultset_row_count = 0;
	cursor->resultset_col_count = 0;
	cursor->resultset_col_type_offset = 0;
	cursor->resultset_col_name_offset = 0;
	cursor->resultset_content_offset = 0;
	cursor->resultset_current_offset = 0;
	cursor->resultset_current_row_count = 0;
	ret = security_server_shared_file_reopen(path, &(cursor->resultset_fd));
	if (ret != SECURITY_SERVER_API_SUCCESS)
	{
		SECURE_LOGE("unable to open resultset file(%s): %d", path, errno);
		goto EXCEPTION;
	}

	cursor->resultset_path = strdup(path);
	if (!cursor->resultset_path)
	{
		SECURE_LOGE("unable to assign path to resultset file: %d", errno);
		close(cursor->resultset_fd);
		goto EXCEPTION;
	}

	return cursor;

EXCEPTION:
	free(cursor);
	return NULL;
}

int datacontrol_sql_step_next(resultset_cursor *cursor)
{
	int total_col_name_size = 0;
	int ret = 0;
	int fd = cursor->resultset_fd;
	if (cursor->resultset_current_offset == 0)
	{
		ret = lseek(fd, 0, SEEK_SET);
		if (ret < 0)
		{
			LOGE("unable to seek to beginning in the resultset file: %d", errno);
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = read(fd, &(cursor->resultset_row_count), sizeof(int));
		if (ret <= 0)
		{
			LOGE("unable to read the resultset file: %d", errno);
			return DATACONTROL_ERROR_IO_ERROR;
		}

		if (cursor->resultset_row_count > MAX_ROW_COUNT || cursor->resultset_row_count < 1)
		{
			LOGE("tainted row count : %d", cursor->resultset_row_count);
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = read(fd, &(cursor->resultset_col_count), sizeof(int));
		if (ret <= 0)
		{
			LOGE("unable to read the resultset file: %d", errno);
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = read(fd, &(total_col_name_size), sizeof(int));
		if (ret <= 0)
		{
			LOGE("unable to read the resultset file: %d", errno);
			return DATACONTROL_ERROR_IO_ERROR;
		}

		cursor->resultset_col_type_offset = sizeof(int) * 3;
		cursor->resultset_col_name_offset = cursor->resultset_col_type_offset + (cursor->resultset_col_count) * sizeof(int);
		cursor->resultset_content_offset = cursor->resultset_col_name_offset + total_col_name_size;

		cursor->resultset_current_offset = cursor->resultset_content_offset;

		row_offset_list = (int *)malloc((cursor->resultset_row_count) * (sizeof(int)));
		if (!row_offset_list)
		{
			LOGE("unable to create row_offset_list");
			return DATACONTROL_ERROR_OUT_OF_MEMORY;
		}

		int counter = 0;
		for (counter = 0; counter < cursor->resultset_row_count; counter++)
		{
			row_offset_list[counter] = 0;
		}
		row_offset_list[cursor->resultset_current_row_count] = cursor->resultset_current_offset;
	}
	else
	{
		if (!(cursor->resultset_current_row_count < (cursor->resultset_row_count -1)))
		{
			LOGE("Reached to the end of the result set");
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = row_offset_list[cursor->resultset_current_row_count + 1];
		if (ret == 0) // Move to next offset
		{
			int size = 0;
			int i = 0;

			ret = lseek(fd, cursor->resultset_current_offset, SEEK_SET);
			if (ret < 0)
			{
				LOGE("unable to seek in the resultset file: %d", errno);
				return DATACONTROL_ERROR_IO_ERROR;
			}

			for (i = 0; i < cursor->resultset_col_count; i++)
			{
				ret = lseek(fd, sizeof(int), SEEK_CUR);
				if (ret < 0)
				{
					LOGE("unable to seek in the resultset file: %d", errno);
					return DATACONTROL_ERROR_IO_ERROR;
				}

				ret = read(fd, &size, sizeof(int));
				if (ret == 0)
				{
					LOGE("unable to read the resultset file: %d", errno);
					return DATACONTROL_ERROR_IO_ERROR;
				}

				ret = lseek(fd, size, SEEK_CUR);
				if (ret < 0)
				{
					LOGE("unable to seek in the resultset file: %d", errno);
					return DATACONTROL_ERROR_IO_ERROR;
				}

				cursor->resultset_current_offset += sizeof(int) * 2 + size;
			}

			row_offset_list[cursor->resultset_current_row_count + 1] = cursor->resultset_current_offset;
		}
		else
		{
			cursor->resultset_current_offset = row_offset_list[cursor->resultset_current_row_count + 1];
		}
		cursor->resultset_current_row_count++;

	}
	return DATACONTROL_ERROR_NONE;
}

int datacontrol_sql_step_last(resultset_cursor *cursor)
{
	int ret = 0;

	if (cursor->resultset_row_count > MAX_ROW_COUNT || cursor->resultset_row_count < 1)
	{
		LOGE("tainted row count : %d", cursor->resultset_row_count);
		return DATACONTROL_ERROR_IO_ERROR;
	}

	if (cursor->resultset_current_row_count == (cursor->resultset_row_count - 1))
	{
		return DATACONTROL_ERROR_NONE; // Already @ last row
	}

	if (!row_offset_list)
	{
		ret = datacontrol_sql_step_next(cursor); // make a first move
		if (ret != DATACONTROL_ERROR_NONE)
		{
			return ret;
		}

		if (cursor->resultset_row_count > MAX_ROW_COUNT || cursor->resultset_row_count < 1)
		{
			LOGE("tainted row count : %d", cursor->resultset_row_count);
			return DATACONTROL_ERROR_IO_ERROR;
		}
	}

	// check if the rowOffsetList contains last row offset
	if (row_offset_list && row_offset_list[cursor->resultset_row_count - 1] != 0)
	{
		cursor->resultset_current_offset = row_offset_list[cursor->resultset_row_count - 1];
		cursor->resultset_current_row_count = cursor->resultset_row_count - 1;
	}
	else
	{
		int i = 0;
		// Move till last row offset.
		for (i = (cursor->resultset_current_row_count + 1); i < cursor->resultset_row_count; i++)
		{
			ret = datacontrol_sql_step_next(cursor); // move till last row data offset
			if (ret != DATACONTROL_ERROR_NONE)
			{
				return ret;
			}

		}
	}

	return DATACONTROL_ERROR_NONE;
}


int datacontrol_sql_step_first(resultset_cursor *cursor)
{
	if (cursor->resultset_current_offset > 0)
	{
		cursor->resultset_current_offset = cursor->resultset_content_offset;
		cursor->resultset_current_row_count = 0;
		return DATACONTROL_ERROR_NONE;
	}

	// MoveFirst is called for the first time before MoveNext() or MoveLast()
	cursor->resultset_current_offset = 0;
	return datacontrol_sql_step_next(cursor);
}


int datacontrol_sql_step_previous(resultset_cursor *cursor)
{
	if ((cursor->resultset_current_row_count - 1) < 0)
	{
		LOGE("invalid request");
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}
	cursor->resultset_current_offset = row_offset_list[cursor->resultset_current_row_count - 1];
	cursor->resultset_current_row_count--;

	return DATACONTROL_ERROR_NONE;
}


int datacontrol_sql_get_column_count(resultset_cursor *cursor)
{
	return cursor->resultset_col_count;
}

int datacontrol_sql_get_column_name(resultset_cursor *cursor, int column_index, char *name)
{
	char col_name[4096] = {0, };
	int i = 0;
	int ret = 0;
	FILE *fp = NULL;
	int resultset_fd = 0;

	resultset_fd = dup(cursor->resultset_fd);
	if (resultset_fd < 0)
	{
		LOGE("unable to dup resultset_fd: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	fp = fdopen(resultset_fd, "r");
	if (fp == NULL)
	{
		LOGE("unable to open resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	ret = fseek(fp, cursor->resultset_col_name_offset, SEEK_SET);
	if (ret < 0)
	{
		LOGE("unable to seek in the resultset file: %s", strerror(errno));
		fclose(fp);
		return DATACONTROL_ERROR_IO_ERROR;
	}

	for (i = 0; i < column_index + 1; i++)
	{
		if (!(fgets(col_name, 4096, fp)))
		{
			LOGE("unable to read a line in the resultset file: %s", strerror(errno));
			fclose(fp);
			return DATACONTROL_ERROR_IO_ERROR;
		}
	}

	memset(name, 0, strlen(col_name)); // To avoid copying newline
	memcpy(name, col_name, strlen(col_name) - 1);

	LOGI("The column name is %s", name);

	fclose(fp);
	return DATACONTROL_ERROR_NONE;
}


int datacontrol_sql_get_column_item_size(resultset_cursor *cursor, int column_index)
{
	int type = -1;
	int size = 0;
	int i = 0;
	int ret = 0;

	int fd = cursor->resultset_fd;

	ret = lseek(fd, cursor->resultset_current_offset, SEEK_SET);
	if (ret < 0)
	{
		LOGE("unable to seek in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	for (i = 0; i < column_index; i++) // move to column index
	{
		ret = read(fd, &type, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = read(fd, &size, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = lseek(fd, size, SEEK_CUR);
		if (ret < 0)
		{
			LOGE("unable to seek in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}
	}

	ret = read(fd, &type, sizeof(int));
	if (ret == 0)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	ret = read(fd, &size, sizeof(int));
	if (ret == 0)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	return size;
}


int datacontrol_sql_get_column_item_type(resultset_cursor *cursor, int column_index, datacontrol_sql_column_type* col_type)
{
	int type = -1;
	int i = 0;
	int size = 0;
	int ret = 0;

	int fd = cursor->resultset_fd;

	ret = lseek(fd, cursor->resultset_current_offset, SEEK_SET);
	if (ret < 0)
	{
		LOGE("unable to seek in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	for (i = 0; i < column_index; i++) // move to column index
	{
		ret = read(fd, &type, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = read(fd, &size, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = lseek(fd, size, SEEK_CUR);
		if (ret < 0)
		{
			LOGE("unable to seek in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}
	}

	ret = read(fd, &type, sizeof(int));
	if (ret == 0)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	switch (type)
	{
	case DATACONTROL_SQL_COLUMN_TYPE_INT64:
		*col_type = DATACONTROL_SQL_COLUMN_TYPE_INT64;
		break;

	case DATACONTROL_SQL_COLUMN_TYPE_DOUBLE:
		*col_type = DATACONTROL_SQL_COLUMN_TYPE_DOUBLE;
		break;

	case DATACONTROL_SQL_COLUMN_TYPE_TEXT:
		*col_type = DATACONTROL_SQL_COLUMN_TYPE_TEXT;
		break;

	case DATACONTROL_SQL_COLUMN_TYPE_BLOB:
		*col_type = DATACONTROL_SQL_COLUMN_TYPE_BLOB;
		break;

	case DATACONTROL_SQL_COLUMN_TYPE_NULL:
		*col_type = DATACONTROL_SQL_COLUMN_TYPE_NULL;
		break;

	default:
		*col_type = DATACONTROL_SQL_COLUMN_TYPE_UNDEFINED;
		break;
	}

	return DATACONTROL_ERROR_NONE;
}


int datacontrol_sql_get_blob_data(resultset_cursor *cursor, int column_index, void *buffer, int data_size)
{
	int type = -1;
	int size = 0;
	int i = 0;
	int ret = 0;

	int fd = cursor->resultset_fd;

	ret = lseek(fd, cursor->resultset_current_offset, SEEK_SET);
	if (ret < 0)
	{
		LOGE("unable to seek in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	for (i = 0; i < column_index; i++) // move to column index
	{
		ret = read(fd, &type, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = read(fd, &size, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = lseek(fd, size, SEEK_CUR);
		if (ret < 0)
		{
			LOGE("unable to seek in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}
	}

	ret = read(fd, &type, sizeof(int));
	if (ret == 0)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	if (type != (int)DATACONTROL_SQL_COLUMN_TYPE_BLOB)
	{
		LOGE("type mismatch: requested for BLOB type but %d present:", type);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	ret = read(fd, &size, sizeof(int));
	if (size > data_size)
	{
		LOGE("size is more than the size requested");
		return DATACONTROL_ERROR_MAX_EXCEEDED; //overflow
	}

	if (size > 0)
	{
		char *data = (char*)malloc((size + 1) * (sizeof(char)));
		if (data == NULL) {
			LOGE("out of memory");
			return DATACONTROL_ERROR_OUT_OF_MEMORY;
		}

		memset(data, 0, size + 1);

		ret = read(fd, data, size);
		if (ret < size)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			free(data);
			return DATACONTROL_ERROR_IO_ERROR;
		}

		memcpy(buffer, data, size + 1);
		free(data);
	}
	return DATACONTROL_ERROR_NONE;
}


int datacontrol_sql_get_int_data(resultset_cursor *cursor, int column_index, int *data)
{
	long long long_value = 0;
	int ret = -1;

	ret = datacontrol_sql_get_int64_data(cursor, column_index, &long_value);
	if (ret == 0)
	{
		*data = (int) long_value;
	}

	return ret;
}


int datacontrol_sql_get_int64_data(resultset_cursor *cursor, int column_index, long long *data)
{
	int type = -1;
	int size = 0;
	int i = 0;
	int ret = 0;

	int fd = cursor->resultset_fd;

	ret = lseek(fd, cursor->resultset_current_offset, SEEK_SET);
	if (ret < 0)
	{
		LOGE("unable to seek in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	for (i = 0; i < column_index; i++) // move to column index
	{
		ret = read(fd, &type, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = read(fd, &size, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = lseek(fd, size, SEEK_CUR);
		if (ret < 0)
		{
			LOGE("unable to seek in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}
	}

	ret = read(fd, &type, sizeof(int));
	if (ret == 0)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	if (type != (int)DATACONTROL_SQL_COLUMN_TYPE_INT64)
	{
		LOGE("type mismatch: requested for int type but %d present:", type);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	ret = read(fd, &size, sizeof(int));
	if (ret == 0)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	ret = read(fd, data, size);
	if (ret < size)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	return DATACONTROL_ERROR_NONE;
}

int datacontrol_sql_get_double_data(resultset_cursor *cursor, int column_index, double *data)
{
	int type = -1;
	int size = 0;
	int i = 0;
	int ret = 0;

	int fd = cursor->resultset_fd;

	ret = lseek(fd, cursor->resultset_current_offset, SEEK_SET);
	if (ret < 0)
	{
		LOGE("unable to seek in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	for (i = 0; i < column_index; i++) // move to column index
	{
		ret = read(fd, &type, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = read(fd, &size, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = lseek(fd, size, SEEK_CUR);
		if (ret < 0)
		{
			LOGE("unable to seek in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}
	}

	ret = read(fd, &type, sizeof(int));
	if (ret == 0)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	if (type != (int)DATACONTROL_SQL_COLUMN_TYPE_DOUBLE)
	{
		LOGE("type mismatch: requested for double type but %d present:", type);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	ret = read(fd, &size, sizeof(int));
	if (ret == 0)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	ret = read(fd, data, size);
	if (ret < size)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	return DATACONTROL_ERROR_NONE;
}


int datacontrol_sql_get_text_data(resultset_cursor *cursor, int column_index, char *buffer)
{
	int type = -1;
	int size = 0;
	int i = 0;
	int ret = 0;

	int fd = cursor->resultset_fd;

	ret = lseek(fd, cursor->resultset_current_offset, SEEK_SET);
	if (ret < 0)
	{
		LOGE("unable to seek in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	for (i = 0; i < column_index; i++) // move to column index
	{
		ret = read(fd, &type, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = read(fd, &size, sizeof(int));
		if (ret == 0)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}

		ret = lseek(fd, size, SEEK_CUR);
		if (ret < 0)
		{
			LOGE("unable to seek in the resultset file: %s", strerror(errno));
			return DATACONTROL_ERROR_IO_ERROR;
		}
	}

	ret = read(fd, &type, sizeof(int));
	if (ret == 0)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	if (type != (int)DATACONTROL_SQL_COLUMN_TYPE_TEXT)
	{
		LOGE("type mismatch: requested for text type but %d present:", type);
		return DATACONTROL_ERROR_INVALID_PARAMETER;
	}

	ret = read(fd, &size, sizeof(int));
	if (ret == 0)
	{
		LOGE("unable to read in the resultset file: %s", strerror(errno));
		return DATACONTROL_ERROR_IO_ERROR;
	}

	if (size > 0)
	{
		char *data = (char*)malloc((size + 1) * (sizeof(char)));
		if(!data)
		{
			LOGE("unable to create buffer to read");
			return DATACONTROL_ERROR_OUT_OF_MEMORY;
		}

		memset(data, 0, size + 1);
		ret = read(fd, data, size);
		if (ret < size)
		{
			LOGE("unable to read in the resultset file: %s", strerror(errno));
			free(data);
			return DATACONTROL_ERROR_IO_ERROR;
		}

		memcpy(buffer, data, size + 1);
		free(data);
	}

	return DATACONTROL_ERROR_NONE;
}


int datacontrol_sql_remove_cursor(resultset_cursor *cursor)
{
	close(cursor->resultset_fd);

	int ret = security_server_shared_file_delete(cursor->resultset_path);
	if (ret != SECURITY_SERVER_API_SUCCESS)
	{
		LOGE("unable to remove map query result file: %d", ret);
	}

	free(row_offset_list);
	row_offset_list = 0;

	free(cursor->resultset_path);
	free(cursor);

	return DATACONTROL_ERROR_NONE;
}
