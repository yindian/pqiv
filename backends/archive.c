/**
 * pqiv
 *
 * Copyright (c) 2013-2017, Phillip Berndt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * libarchive backend
 *
 * This is the non-comicbook variant that handles arbitrary archives
 * (recursively, if necessary).
 *
 */

#include "../pqiv.h"
#include "../lib/filebuffer.h"
#include <archive.h>
#include <archive_entry.h>
#include <string.h>
#include <stdlib.h>

#if ARCHIVE_VERSION_NUMBER > 3001002
#define WITH_EXTERNAL_UNPACKER
#endif

#ifdef WITH_EXTERNAL_UNPACKER
typedef enum {
	X_BUILTIN = 0,
	X_7ZIP,
	X_NUM_UNPACKERS
} unpacker_e;
static gchar *unpacker_path[X_NUM_UNPACKERS] = {NULL};
#endif

typedef struct {
	// The source archive
	file_t *source_archive;

	// The path to the target file within the archive
	gchar *entry_name;
#ifdef WITH_EXTERNAL_UNPACKER
	size_t entry_size;
	gboolean check_pass;
	unpacker_e tool;
#endif
} file_loader_delegate_archive_t;

#if ARCHIVE_VERSION_NUMBER > 3001002
static int pass_inited = 0;
static GList *pass_list = NULL;
static void do_parse_passphrase_file(const gchar *filename) {/*{{{*/
	GFile *f = g_file_new_for_path(filename);
	GFileInputStream *fis = g_file_read(f, NULL, NULL);
	if (fis) {
		GDataInputStream *dis = g_data_input_stream_new(G_INPUT_STREAM(fis));
		if (dis) {
			char *line;
			gsize len;
			while ((line = g_data_input_stream_read_line(dis, &len, NULL, NULL)) != NULL) {
#ifdef WITH_EXTERNAL_UNPACKER
				gchar *s = g_strdup_printf("-p%s", line);
				if (s) {
					pass_list = g_list_append(pass_list, s + 2);
				}
				(void) len;
#else
				pass_list = g_list_append(pass_list, g_strndup(line, len));
#endif
			}
			g_object_unref(dis);
		}
		g_object_unref(fis);
	}
	g_object_unref(f);
}/*}}}*/
static void parse_passphrase_file() {/*{{{*/
	// Check for a configuration file
	GQueue *test_dirs = g_queue_new();
	const gchar *env_config_file = g_getenv("PQIVPASS");
	if(env_config_file) {
		g_queue_push_tail(test_dirs, g_strdup(env_config_file));
	}
	const gchar *config_dir = g_getenv("XDG_CONFIG_HOME");
	if(!config_dir) {
		g_queue_push_tail(test_dirs, g_build_filename(g_getenv("HOME"), ".config", "pqivpass", NULL));
	}
	else {
		g_queue_push_tail(test_dirs, g_build_filename(config_dir, "pqivpass", NULL));
	}
	g_queue_push_tail(test_dirs, g_build_filename(g_getenv("HOME"), ".pqivpass", NULL));
	const gchar *system_config_dirs = g_getenv("XDG_CONFIG_DIRS");
	if(system_config_dirs) {
		gchar **split_system_config_dirs = g_strsplit(system_config_dirs, ":", 0);
		for(gchar **system_dir = split_system_config_dirs; *system_dir; system_dir++) {
			g_queue_push_tail(test_dirs, g_build_filename(*system_dir, "pqivpass", NULL));
		}
		g_strfreev(split_system_config_dirs);
	}
	g_queue_push_tail(test_dirs, g_build_filename(G_DIR_SEPARATOR_S "etc", "pqivpass", NULL));

	gchar *pass_file_name;
	while((pass_file_name = g_queue_pop_head(test_dirs))) {
		if(g_file_test(pass_file_name, G_FILE_TEST_EXISTS)) {
			do_parse_passphrase_file(pass_file_name);
			g_free(pass_file_name);
			break;
		}
		g_free(pass_file_name);
	}

	while((pass_file_name = g_queue_pop_head(test_dirs))) {
		g_free(pass_file_name);
	}
	g_queue_free(test_dirs);
	pass_inited = 1;
}/*}}}*/
#endif

static struct archive *file_type_archive_gen_archive(GBytes *data) {/*{{{*/
	struct archive *archive = archive_read_new();
	archive_read_support_format_zip(archive);
	archive_read_support_format_rar(archive);
	archive_read_support_format_7zip(archive);
	archive_read_support_format_tar(archive);
	archive_read_support_filter_all(archive);
#if ARCHIVE_VERSION_NUMBER > 3001002
	if (!pass_inited) {
		parse_passphrase_file();
	}
	if (pass_list) {
		GList *pass;
		for (pass = pass_list; pass; pass = g_list_next(pass)) {
			archive_read_add_passphrase(archive, pass->data);
		}
	}
#endif

	gsize data_size;
	char *data_ptr = (char *)g_bytes_get_data(data, &data_size);

	if(archive_read_open_memory(archive, data_ptr, data_size) != ARCHIVE_OK) {
		g_printerr("Failed to load archive: %s\n", archive_error_string(archive));
		archive_read_free(archive);
		return NULL;
	}

	return archive;
}/*}}}*/

void file_type_archive_data_free(file_loader_delegate_archive_t *data) {/*{{{*/
	if(data->source_archive) {
		file_free(data->source_archive);
		data->source_archive = NULL;
	}
	g_free(data);
}/*}}}*/

GBytes *file_type_archive_data_loader(file_t *file, GError **error_pointer) {/*{{{*/
	const file_loader_delegate_archive_t *archive_data = g_bytes_get_data(file->file_data, NULL);
#ifdef WITH_EXTERNAL_UNPACKER
	if (archive_data->tool != X_BUILTIN) {
		const gchar *argv[] = {
			unpacker_path[archive_data->tool],
			"-p",
			"-ba",
			"-so",
			"e",
			archive_data->source_archive->file_name,
			archive_data->entry_name,
			NULL
		};
		gchar *output, *error;
		gint exit_status;
		if (archive_data->check_pass) {
			GList *pass;
			for (pass = pass_list; pass; pass = g_list_next(pass)) {
				argv[1] = (gchar *) pass->data - 2;
				if (g_spawn_sync(NULL, (gchar **) argv, NULL, G_SPAWN_DEFAULT, NULL, NULL, &output, &error, &exit_status, error_pointer)) {
					if (g_spawn_check_exit_status(exit_status, error_pointer)) {
						g_free(error);
						pass_list = g_list_remove_link(pass_list, pass);
						pass_list = g_list_concat(pass, pass_list);
						return g_bytes_new_take(output, archive_data->entry_size);
					}
					else {
						g_clear_error(error_pointer);
						if (strstr(error, "Unsupported Method")) {
							*error_pointer = g_error_new(g_quark_from_static_string("pqiv-archive-error"), 1, "%s", g_strchomp(error));
							g_free(output);
							g_free(error);
							return NULL;
						}
						g_free(output);
						g_free(error);
					}
				}
				else {
					g_printerr("Failed to spawn unpacker to load archive %s: %s\n", file->display_name, error_pointer && *error_pointer ? (*error_pointer)->message : "Unknown error");
					g_clear_error(error_pointer);
					return NULL;
				}
			}
		}
		{
			argv[1] = "-p";
			if (g_spawn_sync(NULL, (gchar **) argv, NULL, G_SPAWN_DEFAULT, NULL, NULL, &output, &error, &exit_status, error_pointer)) {
				if (g_spawn_check_exit_status(exit_status, error_pointer)) {
					g_free(error);
					return g_bytes_new_take(output, archive_data->entry_size);
				}
				else {
					g_printerr("Failed to unpack archive %s: %s\n", file->display_name, error_pointer && *error_pointer ? (*error_pointer)->message : "Unknown error");
					g_clear_error(error_pointer);
					*error_pointer = g_error_new(g_quark_from_static_string("pqiv-archive-error"), 1, "%s", g_strchomp(error));
					g_free(output);
					g_free(error);
					return NULL;
				}
			}
			else {
				g_printerr("Failed to spawn unpacker to load archive %s: %s\n", file->display_name, error_pointer && *error_pointer ? (*error_pointer)->message : "Unknown error");
				g_clear_error(error_pointer);
				return NULL;
			}
		}
	}
#endif

	GBytes *data = buffered_file_as_bytes(archive_data->source_archive, NULL, error_pointer);
	if(!data) {
		g_printerr("Failed to load archive %s: %s\n", file->display_name, error_pointer && *error_pointer ? (*error_pointer)->message : "Unknown error");
		g_clear_error(error_pointer);
		return NULL;
	}

	struct archive *archive = file_type_archive_gen_archive(data);
	if(!archive) {
		buffered_file_unref(archive_data->source_archive);
		return NULL;
	}

	// Find the proper entry
	size_t entry_size = 0;
	void *entry_data = NULL;

	struct archive_entry *entry;
	while(archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
		if(archive_data->entry_name && strcmp(archive_data->entry_name, archive_entry_pathname(entry)) == 0) {
			entry_size = archive_entry_size(entry);
			entry_data = g_malloc(entry_size);

			if(archive_read_data(archive, entry_data, entry_size) != (ssize_t)entry_size) {
				*error_pointer = g_error_new(g_quark_from_static_string("pqiv-archive-error"), 1, "The file had an unexpected size : %s", archive_error_string(archive));
				archive_read_free(archive);
				buffered_file_unref(archive_data->source_archive);
#if 0
				*error_pointer = g_error_new(g_quark_from_static_string("pqiv-archive-error"), 1, "The file had an unexpected size");
#endif
				return NULL;
			}

			break;
		}
	}

	archive_read_free(archive);
	buffered_file_unref(archive_data->source_archive);
	if(!entry_size) {
		*error_pointer = g_error_new(g_quark_from_static_string("pqiv-archive-error"), 1, "The file has gone within the archive");
		return NULL;
	}

	return g_bytes_new_take(entry_data, entry_size);
}/*}}}*/

BOSNode *file_type_archive_alloc(load_images_state_t state, file_t *file) {/*{{{*/
	GError *error_pointer = NULL;
	GBytes *data = buffered_file_as_bytes(file, NULL, &error_pointer);
	if(!data) {
		g_printerr("Failed to load archive %s: %s\n", file->display_name, error_pointer ? error_pointer->message : "Unknown error");
		g_clear_error(&error_pointer);
		file_free(file);
		return FALSE_POINTER;
	}

	struct archive *archive = file_type_archive_gen_archive(data);
	if(!archive) {
		buffered_file_unref(file);
		file_free(file);
		return FALSE_POINTER;
	}

	GtkFileFilterInfo file_filter_info;
	file_filter_info.contains = GTK_FILE_FILTER_FILENAME | GTK_FILE_FILTER_DISPLAY_NAME;

	BOSNode *first_node = FALSE_POINTER;

	struct archive_entry *entry;
#ifdef WITH_EXTERNAL_UNPACKER
	BOSNode *last_node = NULL;
	unpacker_e tool = X_BUILTIN;
	int ret = archive_read_next_header(archive, &entry);
	int format = archive_format(archive);
	switch (format)
	{
		case ARCHIVE_FORMAT_RAR:
		case ARCHIVE_FORMAT_7ZIP:
#if ARCHIVE_VERSION_NUMBER >= 3004000
		case ARCHIVE_FORMAT_RAR_V5:
#endif
			if (unpacker_path[X_7ZIP] == NULL) {
				gchar *path = g_find_program_in_path("7z");
				unpacker_path[X_7ZIP] = path ? path : FALSE_POINTER;
			}
			if (unpacker_path[X_7ZIP] != FALSE_POINTER) {
				tool = X_7ZIP;
			}
			break;
		default:
			break;
	}
	while(ret == ARCHIVE_OK) {
#else
	while(archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
#endif
        mode_t filetype = archive_entry_filetype(entry);
        if (S_ISDIR(filetype)) {
            archive_read_data_skip(archive);
#ifdef WITH_EXTERNAL_UNPACKER
			ret = archive_read_next_header(archive, &entry);
#endif
            continue;
        }
		const gchar *entry_name = archive_entry_pathname(entry);

		#if ARCHIVE_VERSION_NUMBER < 3003002
			// Affected by libarchive bug #869
			if(archive_entry_size(entry) == 0) {
				const char *archive_format = archive_format_name(archive);
				if(strncmp("ZIP", archive_format, 3) == 0) {
					g_printerr("Failed to load archive %s: This ZIP file is affected by libarchive bug #869, which was fixed in v3.3.2. Skipping file.\n", file->display_name);
					archive_read_free(archive);
					buffered_file_unref(file);
					file_free(file);
					return FALSE_POINTER;
				}
			}
		#endif


		// Prepare a new file_t for this entry
		gchar *sub_name = g_strdup_printf("%s#%s", file->display_name, entry_name);
#if ARCHIVE_VERSION_NUMBER <= 3001900
		file_t *new_file = image_loader_duplicate_file(file, g_strdup(sub_name), g_strdup(sub_name), sub_name);
#else
		const gchar *entry_name_utf8 = g_utf8_validate(entry_name, -1, NULL) ? entry_name : archive_entry_pathname_utf8(entry);
		if (entry_name_utf8 == NULL) {
			entry_name_utf8 = g_convert(entry_name, -1, "utf-8", "cp936", NULL, NULL, NULL);
			if (entry_name_utf8 == NULL) {
				entry_name_utf8 = g_str_to_ascii(entry_name, NULL);
			}
		}
		gchar *sub_name_utf8 = g_strdup_printf("%s#%s", file->display_name, entry_name_utf8);
		file_t *new_file = image_loader_duplicate_file(file, g_strdup(sub_name), sub_name_utf8, sub_name);
#endif
		if(new_file->file_data) {
			g_bytes_unref(new_file->file_data);
			new_file->file_data = NULL;
		}
		size_t delegate_struct_alloc_size = sizeof(file_loader_delegate_archive_t) + strlen(entry_name) + 2;
		file_loader_delegate_archive_t *new_file_data = g_malloc(delegate_struct_alloc_size);
		new_file_data->source_archive = image_loader_duplicate_file(file, NULL, NULL, NULL);
		new_file_data->entry_name     = (char *)(new_file_data) + sizeof(file_loader_delegate_archive_t) + 1;
		memcpy(new_file_data->entry_name, entry_name, strlen(entry_name) + 1);
#ifdef WITH_EXTERNAL_UNPACKER
		new_file_data->entry_size = archive_entry_size(entry);
		if (tool != X_BUILTIN && archive_entry_is_encrypted(entry)) {
			new_file_data->check_pass = TRUE;
			new_file_data->tool = tool;
		}
		else {
			new_file_data->check_pass = FALSE;
			new_file_data->tool = X_BUILTIN;
		}
#endif
		new_file->file_data = g_bytes_new_with_free_func(new_file_data, delegate_struct_alloc_size, (GDestroyNotify)file_type_archive_data_free, new_file_data);
		new_file->file_flags |= FILE_FLAGS_MEMORY_IMAGE;
		new_file->file_data_loader = file_type_archive_data_loader;

		// Find an appropriate handler for this file
		gchar *name_lowerc = g_utf8_strdown(entry_name, -1);
		file_filter_info.filename = file_filter_info.display_name = name_lowerc;

		// Check if one of the file type handlers can handle this file
		BOSNode *node = load_images_handle_parameter_find_handler(entry_name, state, new_file, &file_filter_info);
		if(node == NULL) {
			// No handler found. We could fall back to using a default. Free new_file instead.
			file_free(new_file);
		}
		else if(node == FALSE_POINTER) {
			// File type is known, but loading failed; new_file has already been free()d
			node = NULL;
		}
		else if(first_node == FALSE_POINTER) {
			first_node = node;
			last_node = node;
		}
		else {
			last_node = node;
		}

		g_free(name_lowerc);

		archive_read_data_skip(archive);
#ifdef WITH_EXTERNAL_UNPACKER
		ret = archive_read_next_header(archive, &entry);
#else
		/* } */
#endif
	}

#ifdef WITH_EXTERNAL_UNPACKER
	const char *error_message = archive_error_string(archive);
	if (tool != X_BUILTIN && (
					(first_node == FALSE_POINTER && archive_entry_is_metadata_encrypted(entry)) ||
					(first_node == last_node && error_message && strstr(error_message, " solid ")))) {
		archive_read_free(archive);
		buffered_file_unref(file);
		const gchar *argv[] = {
			unpacker_path[tool],
			"-p",
			"-ba",
			"-slt",
			"l",
			file->file_name,
			NULL
		};
		gchar *output, *error;
		gint exit_status;
		if (first_node == FALSE_POINTER) {
			GList *pass;
			for (pass = pass_list; pass; pass = g_list_next(pass)) {
				argv[1] = (gchar *) pass->data - 2;
				if (g_spawn_sync(NULL, (gchar **) argv, NULL, G_SPAWN_DEFAULT, NULL, NULL, &output, &error, &exit_status, &error_pointer)) {
					if (g_spawn_check_exit_status(exit_status, &error_pointer)) {
						g_free(error);
						pass_list = g_list_remove_link(pass_list, pass);
						pass_list = g_list_concat(pass, pass_list);
						const gchar *entry_name = NULL;
						gchar *p, *q = NULL;
						for (p = output - 1; p; p = q) {
							q = strchr(++p, '\n');
							if (q && q - p > 7) {
								if (strncmp(p, "Path = ", 7) == 0) {
									entry_name = p + 7;
									if (q[-1] == '\r') {
										q[-1] = '\0';
									}
									else {
										*q = '\0';
									}
								}
								else if (strncmp(p, "Size = ", 7) == 0) {
									long entry_size = atol(p + 7);
									if (entry_size && entry_name) {
										gchar *sub_name = g_strdup_printf("%s#%s", file->display_name, entry_name);
										file_t *new_file = image_loader_duplicate_file(file, g_strdup(sub_name), g_strdup(sub_name), sub_name);
										if(new_file->file_data) {
											g_bytes_unref(new_file->file_data);
											new_file->file_data = NULL;
										}
										size_t delegate_struct_alloc_size = sizeof(file_loader_delegate_archive_t) + strlen(entry_name) + 2;
										file_loader_delegate_archive_t *new_file_data = g_malloc(delegate_struct_alloc_size);
										new_file_data->source_archive = image_loader_duplicate_file(file, NULL, NULL, NULL);
										new_file_data->entry_name     = (char *)(new_file_data) + sizeof(file_loader_delegate_archive_t) + 1;
										memcpy(new_file_data->entry_name, entry_name, strlen(entry_name) + 1);
										new_file_data->entry_size = entry_size;
										new_file_data->check_pass = TRUE;
										new_file_data->tool = tool;
										new_file->file_data = g_bytes_new_with_free_func(new_file_data, delegate_struct_alloc_size, (GDestroyNotify)file_type_archive_data_free, new_file_data);
										new_file->file_flags |= FILE_FLAGS_MEMORY_IMAGE;
										new_file->file_data_loader = file_type_archive_data_loader;

										// Find an appropriate handler for this file
										gchar *name_lowerc = g_utf8_strdown(entry_name, -1);
										file_filter_info.filename = file_filter_info.display_name = name_lowerc;

										// Check if one of the file type handlers can handle this file
										BOSNode *node = load_images_handle_parameter_find_handler(entry_name, state, new_file, &file_filter_info);
										if(node == NULL) {
											// No handler found. We could fall back to using a default. Free new_file instead.
											file_free(new_file);
										}
										else if(node == FALSE_POINTER) {
											// File type is known, but loading failed; new_file has already been free()d
											node = NULL;
										}
										else if(first_node == FALSE_POINTER) {
											first_node = node;
										}

										g_free(name_lowerc);
									}
								}
							}
						}
						g_free(output);
						break;
					}
					else {
						if (strstr(error, "Unsupported Method")) {
							g_printerr("Failed to list encrypted archive %s: %s: %s\n", file->display_name, error_pointer ? error_pointer->message : "Unknown error", g_strstrip(error[0] ? error : output));
							g_clear_error(&error_pointer);
							g_free(output);
							g_free(error);
							break;
						}
						g_clear_error(&error_pointer);
						g_free(output);
						g_free(error);
					}
				}
				else {
					g_printerr("Failed to spawn unpacker to list archive %s: %s\n", file->display_name, error_pointer ? error_pointer->message : "Unknown error");
					g_clear_error(&error_pointer);
					break;
				}
			}
		}
		else {
			file_t *first_file = (file_t *) first_node->data;
			const file_loader_delegate_archive_t *first_data = g_bytes_get_data(first_file->file_data, NULL);
			const gchar *first_entry_name = first_data->entry_name;
			if (g_spawn_sync(NULL, (gchar **) argv, NULL, G_SPAWN_DEFAULT, NULL, NULL, &output, &error, &exit_status, &error_pointer)) {
				{
					const gchar *entry_name = NULL;
					gchar *p, *q = NULL;
					gboolean first = TRUE;
					for (p = output - 1; p; p = q) {
						q = strchr(++p, '\n');
						if (q && q - p > 7) {
							if (strncmp(p, "Path = ", 7) == 0) {
								entry_name = p + 7;
								if (q[-1] == '\r') {
									q[-1] = '\0';
								}
								else {
									*q = '\0';
								}
							}
							else if (strncmp(p, "Size = ", 7) == 0) {
								long entry_size = atol(p + 7);
								if (entry_size && entry_name) {
									if (first) {
										first = FALSE;
										if (strcmp(entry_name, first_entry_name) == 0) {
											continue;
										}
										else {
											g_printerr("Unexpected first entry for solid archive: should be %s, got %s\n", first_entry_name, entry_name);
										}
									}
									gchar *sub_name = g_strdup_printf("%s#%s", file->display_name, entry_name);
									file_t *new_file = image_loader_duplicate_file(file, g_strdup(sub_name), g_strdup(sub_name), sub_name);
									if(new_file->file_data) {
										g_bytes_unref(new_file->file_data);
										new_file->file_data = NULL;
									}
									size_t delegate_struct_alloc_size = sizeof(file_loader_delegate_archive_t) + strlen(entry_name) + 2;
									file_loader_delegate_archive_t *new_file_data = g_malloc(delegate_struct_alloc_size);
									new_file_data->source_archive = image_loader_duplicate_file(file, NULL, NULL, NULL);
									new_file_data->entry_name     = (char *)(new_file_data) + sizeof(file_loader_delegate_archive_t) + 1;
									memcpy(new_file_data->entry_name, entry_name, strlen(entry_name) + 1);
									new_file_data->entry_size = entry_size;
									new_file_data->check_pass = TRUE;
									new_file_data->tool = tool;
									new_file->file_data = g_bytes_new_with_free_func(new_file_data, delegate_struct_alloc_size, (GDestroyNotify)file_type_archive_data_free, new_file_data);
									new_file->file_flags |= FILE_FLAGS_MEMORY_IMAGE;
									new_file->file_data_loader = file_type_archive_data_loader;

									// Find an appropriate handler for this file
									gchar *name_lowerc = g_utf8_strdown(entry_name, -1);
									file_filter_info.filename = file_filter_info.display_name = name_lowerc;

									// Check if one of the file type handlers can handle this file
									BOSNode *node = load_images_handle_parameter_find_handler(entry_name, state, new_file, &file_filter_info);
									if(node == NULL) {
										// No handler found. We could fall back to using a default. Free new_file instead.
										file_free(new_file);
									}
									else if(node == FALSE_POINTER) {
										// File type is known, but loading failed; new_file has already been free()d
										node = NULL;
									}

									g_free(name_lowerc);
								}
							}
						}
					}
				}
				if (!g_spawn_check_exit_status(exit_status, &error_pointer)) {
					g_printerr("Failed to list solid archive %s: %s: %s\n", file->display_name, error_pointer ? error_pointer->message : "Unknown error", g_strstrip(error[0] ? error : output));
					g_clear_error(&error_pointer);
				}
				g_free(output);
				g_free(error);
			}
			else {
				g_printerr("Failed to spawn unpacker to list archive %s: %s\n", file->display_name, error_pointer ? error_pointer->message : "Unknown error");
				g_clear_error(&error_pointer);
			}
		}
	}
	else {
		archive_read_free(archive);
		buffered_file_unref(file);
	}
#else
	archive_read_free(archive);
	buffered_file_unref(file);
#endif
	file_free(file);
	return first_node;
}/*}}}*/

void file_type_archive_initializer(file_type_handler_t *info) {/*{{{*/
	// Fill the file filter pattern
	info->file_types_handled = gtk_file_filter_new();

	// Mime types for archives
	gtk_file_filter_add_mime_type(info->file_types_handled, "application/x-tar");
	gtk_file_filter_add_mime_type(info->file_types_handled, "application/x-zip");
	gtk_file_filter_add_mime_type(info->file_types_handled, "application/x-rar");

	// Arbitrary archive files
	gtk_file_filter_add_pattern(info->file_types_handled, "*.zip");
	gtk_file_filter_add_pattern(info->file_types_handled, "*.rar");
	gtk_file_filter_add_pattern(info->file_types_handled, "*.7z");
	gtk_file_filter_add_pattern(info->file_types_handled, "*.tar");
	gtk_file_filter_add_pattern(info->file_types_handled, "*.tbz");
	gtk_file_filter_add_pattern(info->file_types_handled, "*.tgz");
	gtk_file_filter_add_pattern(info->file_types_handled, "*.tar.bz2");
	gtk_file_filter_add_pattern(info->file_types_handled, "*.tar.gz");

	// Assign the handlers
	info->alloc_fn                 =  file_type_archive_alloc;
}/*}}}*/
