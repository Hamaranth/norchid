//
// Created by Samuel Jones on 5/22/22.
//

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef NORCHID_NORCHID_H
#define NORCHID_NORCHID_H

#define CURRENT_DATA_VERSION (1)

#define MIN_DATA_VERSION (1)
#define MAX_DATA_VERSION (1)

enum norchid_entry_type {
    TYPE_HASH_TABLE_ENTRY = 1,
    TYPE_KEY_ENTRY = 2,
    TYPE_VALUE_ENTRY = 3,
    TYPE_EMPTY = 0xFF,
};

enum norchid_sector_status {
    SECTOR_BLANK = 0xFF,
    SECTOR_INITIALIZING = 0x7F,
    SECTOR_INITIALIZED = 0x3F,
    SECTOR_VALID = 0x1F,
};

enum norchid_entry_status {
    ENTRY_BLANK = 0xFF,
    ENTRY_STARTED = 0x7F,
    ENTRY_WRITTEN = 0x3F,
    ENTRY_VALID = 0x1F,
    ENTRY_DELETED = 0x00,
};


typedef bool (*nc_mutex_lock)(void* lock, unsigned int milliseconds);
typedef void (*nc_mutex_unlock)(void* lock);

typedef void (*nc_nor_write)(size_t address, const uint8_t* data, size_t size);
typedef void (*nc_nor_read)(size_t address, const uint8_t* data, size_t size);
typedef void (*nc_nor_erase_sector)(size_t address, size_t size);

struct norchid_platform {
    nc_nor_write write;
    nc_nor_read read;
    nc_nor_erase_sector erase;

    nc_mutex_lock mutex_lock;
    nc_mutex_unlock mutex_unlock;

    void *write_lock;
};

struct norchid_params {
    size_t base_address;
    unsigned int max_lock_delay_ms;
    uint16_t sector_size;
    uint16_t num_sectors;
    uint16_t max_auto_cleanup_iterations;
};

struct norchid_sector_information {
    uint16_t deleted_space;
    uint16_t write_offset;
};


struct norchid_partition {
    struct norchid_params params;
    struct norchid_platform platform;
    struct norchid_sector_information *sector_info;
    uint16_t current_write_sector;
};

struct norchid_iterator {
    uint16_t current_sector;
    uint16_t current_entry_offset;
    struct norchid_partition *partition;
};


enum norchid_status {
    NC_SUCCESS = 0,

    NC_NOT_FOUND = -1,
    NC_ERROR_INTERNAL = -2,
    NC_TRUNCATED = -3,
    NC_LOCK_TIMEOUT = -4,
    NC_INVALID_HEADER = -5,
    NC_INVALID_ENTRY = -6,
};

enum norchid_status norchid_mount_partition(
        struct norchid_partition *partition,
        const struct norchid_params *params,
        const struct norchid_platform *platform,
        struct norchid_sector_information *sector_info);

enum norchid_status norchid_format_partition(struct norchid_partition *partition);

enum norchid_status norchid_put_integer(
        struct norchid_partition *partition,
        const char* key,
        int value);

enum norchid_status norchid_put_string(
        struct norchid_partition *partition,
        const char* key,
        const char* value);

enum norchid_status norchid_put_binary(
        struct norchid_partition *partition,
        const char *key,
        const uint8_t *value,
        size_t len);

enum norchid_status norchid_get_integer(
        struct norchid_partition *partition,
        const char* key,
        int* value);

enum norchid_status norchid_get_string(
        struct norchid_partition *partition,
        const char* key,
        char* value,
        size_t max_len,
        size_t* len);

enum norchid_status norchid_get_binary(
        struct norchid_partition *partition,
        const char* key,
        uint8_t* value,
        size_t max_len,
        size_t* len);

enum norchid_status norchid_exists(
        struct norchid_partition *partition,
        const char *key);

enum norchid_status norchid_open_list(
        struct norchid_partition *partition,
        struct norchid_iterator* iterator);

enum norchid_status norchid_next_key(
        struct norchid_iterator *iterator,
        char* key, size_t max_len, size_t* len);

enum norchid_status norchid_close_list(
        struct norchid_iterator *iterator);

enum norchid_status norchid_cleanup(
        struct norchid_partition *partition);


#endif //NORCHID_NORCHID_H
