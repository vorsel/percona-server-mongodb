/*-
 * Copyright (c) 2014-2020 MongoDB, Inc.
 * Copyright (c) 2008-2014 WiredTiger, Inc.
 *	All rights reserved.
 *
 * See the file LICENSE for redistribution information.
 */

struct __wt_config {
    WT_SESSION_IMPL *session;
    const char *orig;
    const char *end;
    const char *cur;

    int depth, top;
    const int8_t *go;
};

struct __wt_config_check {
    const char *name;
    const char *type;
    int (*checkf)(WT_SESSION_IMPL *, WT_CONFIG_ITEM *);
    const char *checks;
    const WT_CONFIG_CHECK *subconfigs;
    u_int subconfigs_entries;
};

#define WT_CONFIG_REF(session, n) (S2C(session)->config_entries[WT_CONFIG_ENTRY_##n])
struct __wt_config_entry {
    const char *method; /* method name */

#define WT_CONFIG_BASE(session, n) (WT_CONFIG_REF(session, n)->base)
    const char *base; /* configuration base */

    const WT_CONFIG_CHECK *checks; /* check array */
    u_int checks_entries;
};

struct __wt_config_parser_impl {
    WT_CONFIG_PARSER iface;

    WT_SESSION_IMPL *session;
    WT_CONFIG config;
    WT_CONFIG_ITEM config_item;
};

#define WT_CONFIG_ITEM_STATIC_INIT(n) static const WT_CONFIG_ITEM n = {"", 0, 0, WT_CONFIG_ITEM_NUM}

#define WT_CONFIG_UNSET (-1)
/*
 * DO NOT EDIT: automatically built by dist/api_config.py.
 * configuration section: BEGIN
 */
#define WT_CONFIG_ENTRY_WT_CONNECTION_add_collator 0
#define WT_CONFIG_ENTRY_WT_CONNECTION_add_compressor 1
#define WT_CONFIG_ENTRY_WT_CONNECTION_add_data_source 2
#define WT_CONFIG_ENTRY_WT_CONNECTION_add_encryptor 3
#define WT_CONFIG_ENTRY_WT_CONNECTION_add_extractor 4
#define WT_CONFIG_ENTRY_WT_CONNECTION_close 5
#define WT_CONFIG_ENTRY_WT_CONNECTION_debug_info 6
#define WT_CONFIG_ENTRY_WT_CONNECTION_load_extension 7
#define WT_CONFIG_ENTRY_WT_CONNECTION_open_session 8
#define WT_CONFIG_ENTRY_WT_CONNECTION_query_timestamp 9
#define WT_CONFIG_ENTRY_WT_CONNECTION_reconfigure 10
#define WT_CONFIG_ENTRY_WT_CONNECTION_rollback_to_stable 11
#define WT_CONFIG_ENTRY_WT_CONNECTION_set_file_system 12
#define WT_CONFIG_ENTRY_WT_CONNECTION_set_timestamp 13
#define WT_CONFIG_ENTRY_WT_CURSOR_close 14
#define WT_CONFIG_ENTRY_WT_CURSOR_reconfigure 15
#define WT_CONFIG_ENTRY_WT_SESSION_alter 16
#define WT_CONFIG_ENTRY_WT_SESSION_begin_transaction 17
#define WT_CONFIG_ENTRY_WT_SESSION_checkpoint 18
#define WT_CONFIG_ENTRY_WT_SESSION_close 19
#define WT_CONFIG_ENTRY_WT_SESSION_commit_transaction 20
#define WT_CONFIG_ENTRY_WT_SESSION_compact 21
#define WT_CONFIG_ENTRY_WT_SESSION_create 22
#define WT_CONFIG_ENTRY_WT_SESSION_drop 23
#define WT_CONFIG_ENTRY_WT_SESSION_join 24
#define WT_CONFIG_ENTRY_WT_SESSION_log_flush 25
#define WT_CONFIG_ENTRY_WT_SESSION_log_printf 26
#define WT_CONFIG_ENTRY_WT_SESSION_open_cursor 27
#define WT_CONFIG_ENTRY_WT_SESSION_prepare_transaction 28
#define WT_CONFIG_ENTRY_WT_SESSION_query_timestamp 29
#define WT_CONFIG_ENTRY_WT_SESSION_reconfigure 30
#define WT_CONFIG_ENTRY_WT_SESSION_rename 31
#define WT_CONFIG_ENTRY_WT_SESSION_reset 32
#define WT_CONFIG_ENTRY_WT_SESSION_rollback_transaction 33
#define WT_CONFIG_ENTRY_WT_SESSION_salvage 34
#define WT_CONFIG_ENTRY_WT_SESSION_strerror 35
#define WT_CONFIG_ENTRY_WT_SESSION_timestamp_transaction 36
#define WT_CONFIG_ENTRY_WT_SESSION_transaction_sync 37
#define WT_CONFIG_ENTRY_WT_SESSION_truncate 38
#define WT_CONFIG_ENTRY_WT_SESSION_upgrade 39
#define WT_CONFIG_ENTRY_WT_SESSION_verify 40
#define WT_CONFIG_ENTRY_colgroup_meta 41
#define WT_CONFIG_ENTRY_file_config 42
#define WT_CONFIG_ENTRY_file_meta 43
#define WT_CONFIG_ENTRY_index_meta 44
#define WT_CONFIG_ENTRY_lsm_meta 45
#define WT_CONFIG_ENTRY_table_meta 46
#define WT_CONFIG_ENTRY_wiredtiger_open 47
#define WT_CONFIG_ENTRY_wiredtiger_open_all 48
#define WT_CONFIG_ENTRY_wiredtiger_open_basecfg 49
#define WT_CONFIG_ENTRY_wiredtiger_open_usercfg 50
/*
 * configuration section: END
 * DO NOT EDIT: automatically built by dist/flags.py.
 */
