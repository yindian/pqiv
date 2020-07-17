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
 * libarchive backend for comic books
 *
 * This is a stripped down variant of the more advanced archive backend
 * which can only handle *.cb? files, archives for comic book storage.
 * Such files are guaranteed to contain _only_ jpg/png files, which allows
 * to handle them directly using a gdkpixbuf.
 *
 */

#include "../pqiv.h"
#include "../lib/filebuffer.h"
#include <archive.h>
#include <archive_entry.h>
#include <string.h>

typedef struct {
	// The archive object and raw archive data
	gchar *entry_name;

	// The surface where the image is stored.
	cairo_surface_t *image_surface;
} file_private_data_archive_t;

#if ARCHIVE_VERSION_NUMBER > 3001002
#define SUPPORT_PASSPHRASE
#endif
#ifdef SUPPORT_PASSPHRASE
struct archive_read;
extern const char * __archive_read_next_passphrase(struct archive_read *);
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
				pass_list = g_list_append(pass_list, g_strndup(line, len));
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

static struct archive *file_type_archive_cbx_gen_archive(GBytes *data) {/*{{{*/
	struct archive *archive = archive_read_new();
	archive_read_support_format_zip(archive);
	archive_read_support_format_rar(archive);
	archive_read_support_format_7zip(archive);
	archive_read_support_format_tar(archive);
	archive_read_support_filter_all(archive);
#ifdef SUPPORT_PASSPHRASE
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

BOSNode *file_type_archive_cbx_alloc(load_images_state_t state, file_t *file) {/*{{{*/
	GError *error_pointer = NULL;
	GBytes *data = buffered_file_as_bytes(file, NULL, &error_pointer);
	if(!data) {
		g_printerr("Failed to load archive %s: %s\n", file->display_name, error_pointer ? error_pointer->message : "Unknown error");
		g_clear_error(&error_pointer);
		file_free(file);
		return FALSE_POINTER;
	}

	struct archive *archive = file_type_archive_cbx_gen_archive(data);
	if(!archive) {
		file_free(file);
		return FALSE_POINTER;
	}

	BOSNode *first_node = FALSE_POINTER;

	struct archive_entry *entry;
	while(archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
        mode_t filetype = archive_entry_filetype(entry);
        if (S_ISDIR(filetype)) {
            archive_read_data_skip(archive);
            continue;
        }
		const gchar *entry_name = archive_entry_pathname(entry);

#if ARCHIVE_VERSION_NUMBER <= 3001900
		file_t *new_file = image_loader_duplicate_file(file, NULL, g_strdup_printf("%s#%s", file->display_name, entry_name), g_strdup_printf("%s#%s", file->sort_name, entry_name));
#else
		const gchar *entry_name_utf8 = g_utf8_validate(entry_name, -1, NULL) ? entry_name : archive_entry_pathname_utf8(entry);
		if (entry_name_utf8 == NULL) {
			entry_name_utf8 = g_convert(entry_name, -1, "utf-8", "cp936", NULL, NULL, NULL);
			if (entry_name_utf8 == NULL) {
				entry_name_utf8 = g_str_to_ascii(entry_name, NULL);
			}
		}
		gchar *sub_name_utf8 = g_strdup_printf("%s#%s", file->display_name, entry_name_utf8);
		file_t *new_file = image_loader_duplicate_file(file, NULL, sub_name_utf8, g_strdup_printf("%s#%s", file->sort_name, entry_name));
#endif
		new_file->private = g_slice_new0(file_private_data_archive_t);
		((file_private_data_archive_t *)new_file->private)->entry_name = g_strdup(entry_name);

		if(first_node == FALSE_POINTER) {
			first_node = load_images_handle_parameter_add_file(state, new_file);
		}
		else {
			load_images_handle_parameter_add_file(state,  new_file);
		}

		//printf("%s %d\n", archive_entry_pathname(entry), archive_entry_size(entry));
		archive_read_data_skip(archive);
	}

	archive_read_free(archive);
	buffered_file_unref(file);
	file_free(file);
	return first_node;
}/*}}}*/
void file_type_archive_cbx_free(file_t *file) {/*{{{*/
	if(file->private) {
		file_private_data_archive_t *private = (file_private_data_archive_t *)file->private;

		if(private->entry_name) {
			g_free(private->entry_name);
			private->entry_name = NULL;
		}

		g_slice_free(file_private_data_archive_t, file->private);
	}
}/*}}}*/
void file_type_archive_cbx_unload(file_t *file) {/*{{{*/
	file_private_data_archive_t *private = (file_private_data_archive_t *)file->private;

	if(private->image_surface != NULL) {
		cairo_surface_destroy(private->image_surface);
		private->image_surface = NULL;
	}
}/*}}}*/
gboolean file_type_archive_cbx_load_destroy_old_image_callback(gpointer old_surface) {/*{{{*/
	cairo_surface_destroy((cairo_surface_t *)old_surface);
	return FALSE;
}/*}}}*/
void file_type_archive_cbx_load(file_t *file, GInputStream *data_stream, GError **error_pointer) {/*{{{*/
	file_private_data_archive_t *private = (file_private_data_archive_t *)file->private;

	// Open the archive
	GBytes *data = buffered_file_as_bytes(file, data_stream, error_pointer);
	if(!data) {
		return;
	}

#ifdef SUPPORT_PASSPHRASE
	GList *old_pass_list = pass_list;
loop_read_archive:
	(void) 0;
#endif
	struct archive *archive = file_type_archive_cbx_gen_archive(data);
	if(!archive) {
		buffered_file_unref(file);
		*error_pointer = g_error_new(g_quark_from_static_string("pqiv-archive-error"), 1, "Failed to open archive file");
#ifdef SUPPORT_PASSPHRASE
		pass_list = old_pass_list;
#endif
		return;
	}

	// Find the proper entry
	size_t entry_size = 0;
	gchar *entry_data = NULL;

	struct archive_entry *entry;
	while(archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
		if(private->entry_name && strcmp(private->entry_name, archive_entry_pathname(entry)) == 0) {
			entry_size = archive_entry_size(entry);
			entry_data = g_malloc(entry_size);

#if 0
			if(archive_read_data(archive, entry_data, entry_size) != (ssize_t)entry_size) {
#else
#if 0 // for brace pairing only
			}
#endif
			/* request to read extra byte to force CRC check for ZIP archives
			 * cf. zip_read_data_none() */
			if(archive_read_data(archive, entry_data, entry_size + 1) != (ssize_t)entry_size) {
#endif
				*error_pointer = g_error_new(g_quark_from_static_string("pqiv-archive-error"), 1, "The file had an unexpected size : %s", archive_error_string(archive));
#ifdef SUPPORT_PASSPHRASE
				if (archive_entry_is_encrypted(entry) && pass_list) {
					const gchar *next_pass = __archive_read_next_passphrase((struct archive_read *) archive);
					if (next_pass) {
						GList *pass;
						for (pass = pass_list; pass; pass = g_list_next(pass)) {
							if (strcmp(next_pass, pass->data) == 0) {
								g_clear_error(error_pointer);
								pass_list = pass;
								archive_read_free(archive);
								goto loop_read_archive;
							}
						}
					}
				}
				pass_list = old_pass_list;
#endif
				archive_read_free(archive);
				buffered_file_unref(file);
#if 0
				*error_pointer = g_error_new(g_quark_from_static_string("pqiv-archive-error"), 1, "The file had an unexpected size");
#endif
				return;
			}

			break;
		}
	}
#ifdef SUPPORT_PASSPHRASE
	pass_list = old_pass_list;
#endif

	archive_read_free(archive);
	buffered_file_unref(file);
	if(!entry_size) {
		*error_pointer = g_error_new(g_quark_from_static_string("pqiv-archive-error"), 1, "The file has gone within the archive");
		return;
	}

	// Load it as a GdkPixbuf (This could be extended to support animations)
	GInputStream *entry_data_stream = g_memory_input_stream_new_from_data(entry_data, entry_size, g_free);
	GdkPixbuf *pixbuf = gdk_pixbuf_new_from_stream(entry_data_stream, NULL, error_pointer);
	if(!pixbuf) {
		g_object_unref(entry_data_stream);
		return;
	}
	g_object_unref(entry_data_stream);

	GdkPixbuf *new_pixbuf = gdk_pixbuf_apply_embedded_orientation(pixbuf);
	g_object_unref(pixbuf);
	pixbuf = new_pixbuf;

	file->width = gdk_pixbuf_get_width(pixbuf);
	file->height = gdk_pixbuf_get_height(pixbuf);

	// Draw to a cairo surface, see gfkpixbuf.c for why this can not use gdk_cairo_surface_create_from_pixbuf.
	cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, file->width, file->height);
	if(cairo_surface_status(surface) != CAIRO_STATUS_SUCCESS) {
		g_object_unref(pixbuf);
		*error_pointer = g_error_new(g_quark_from_static_string("pqiv-archive-error"), 1, "Failed to create a cairo image surface for the loaded image (cairo status %d)\n", cairo_surface_status(surface));
		return;
	}
	cairo_t *sf_cr = cairo_create(surface);
	gdk_cairo_set_source_pixbuf(sf_cr, pixbuf, 0, 0);
	cairo_paint(sf_cr);
	cairo_destroy(sf_cr);

	cairo_surface_t *old_surface = private->image_surface;
	private->image_surface = surface;
	if(old_surface != NULL) {
		g_idle_add(file_type_archive_cbx_load_destroy_old_image_callback, old_surface);
	}
	g_object_unref(pixbuf);

	file->is_loaded = TRUE;
}/*}}}*/
void file_type_archive_cbx_draw(file_t *file, cairo_t *cr) {/*{{{*/
	file_private_data_archive_t *private = (file_private_data_archive_t *)file->private;

	cairo_surface_t *current_image_surface = private->image_surface;
	cairo_set_source_surface(cr, current_image_surface, 0, 0);
	apply_interpolation_quality(cr);
	cairo_paint(cr);
}/*}}}*/
void file_type_archive_cbx_initializer(file_type_handler_t *info) {/*{{{*/
	// Fill the file filter pattern
	info->file_types_handled = gtk_file_filter_new();

	char pattern[] = { '*', '.', 'c', 'b', '_', '\0' };
	char formats[] = { 'z', 'r', '7', 't', 'a', '\0' };
	for(char *format=formats; *format; format++) {
		pattern[4] = *format;
		gtk_file_filter_add_pattern(info->file_types_handled, pattern);
	}

	// Assign the handlers
	info->alloc_fn                 =  file_type_archive_cbx_alloc;
	info->free_fn                  =  file_type_archive_cbx_free;
	info->load_fn                  =  file_type_archive_cbx_load;
	info->unload_fn                =  file_type_archive_cbx_unload;
	info->draw_fn                  =  file_type_archive_cbx_draw;
}/*}}}*/
