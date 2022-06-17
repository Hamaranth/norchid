//
// Created by Samuel Jones on 5/22/22.
//

#include "norchid.h"
#include <string.h>
#include <stddef.h>

// TODO: what happens if an offset is improperly written?

#define SECTOR_ADDR(partition, sector) (partition->params.base_address + partition->params.sector_size * sector)

// CRC function implementation.

static uint8_t norchid_checksum(const char* key, size_t len, uint8_t crc) {

    static unsigned const char next_crc_table[256] = {
            0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65,
            157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220,
            35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98,
            190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255,
            70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7,
            219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154,
            101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36,
            248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185,
            140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205,
            17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80,
            175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238,
            50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115,
            202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
            87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22,
            233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168,
            116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53
    };

    for (int i=0; i<len; i++) {
        crc = next_crc_table[crc ^ *key++];
    }
    return crc;
}

// Internal structure definitions for flash contents and raw read/write.

#define HASH_TABLE_BIN_COUNT 16

// If updating a value for an existing key, `norchid` will, by default, chain the
// new value onto the old value instead of re-writing a key entry. This can eventually
// slow down key access if we have to follow a long chain. To limit this, there is
// a cap for the number of chains to allow. If we would write a new value that
// would cause a value longer than this number, we instead write a new key
// entry (which extends the chain of keys by one, but starts a new chain of values).
#define MAX_VALUE_CHAIN_DEPTH 8

struct __attribute__((__packed__)) norchid_sector_header {
    char magic[4];
    uint8_t data_version;
    uint8_t status;
    uint16_t length;
    uint16_t replacing;
};

struct __attribute__((__packed__)) norchid_entry_header {
    uint8_t type;
    uint8_t status;
};

struct __attribute__((__packed__)) norchid_hash_table_entry {
    struct norchid_entry_header header;
    uint16_t offsets[HASH_TABLE_BIN_COUNT];
};

struct __attribute__((__packed__)) norchid_key_entry {
    struct norchid_entry_header header;
    uint16_t next_key_offset;
    uint16_t value_offset;
    uint16_t key_length;
};

struct __attribute__((__packed__)) norchid_value_entry {
    struct norchid_entry_header header;
    uint16_t next_value_offset;
    uint16_t value_length;
};

const char *NORCHID_MAGIC = "nchd";

// Raw sector header read/write functions

static inline void raw_read_sector_header(nc_nor_read nor_read, size_t sector_address,
                                                  struct norchid_sector_header* sector_header) {
    nor_read(sector_address, (uint8_t*)sector_header, sizeof(*sector_header));
}

static inline void raw_write_sector_header(nc_nor_write nor_write, size_t sector_address,
                                                  const struct norchid_sector_header* sector_header) {
    nor_write(sector_address, (const uint8_t*)sector_header, sizeof(*sector_header));
}

static inline void raw_update_sector_status(nc_nor_write nor_write, size_t sector_address,
                                                    uint8_t status) {
    const size_t status_offset = 5;
    nor_write(sector_address+status_offset, &status, 1);
}

// Raw entry header read/write functions

static inline void raw_read_entry_header(nc_nor_read nor_read, size_t sector_address, uint16_t offset,
                                          struct norchid_entry_header* entry_header) {
    nor_read(sector_address+offset, (uint8_t*)entry_header, sizeof(*entry_header));
}

static inline void raw_write_entry_header(nc_nor_write nor_write, size_t sector_address, uint16_t offset,
                                                  const struct norchid_entry_header* entry_header) {
    nor_write(sector_address+offset, (const uint8_t*)entry_header, sizeof(*entry_header));
}

static inline void raw_update_entry_status(nc_nor_write nor_write, size_t sector_address, uint16_t offset,
                                                uint8_t status) {
    const size_t status_offset = 1;
    nor_write(sector_address+offset+status_offset, &status, 1);
}

// Hash table entry read/write functions

static inline void raw_read_hash_table_entry(nc_nor_read nor_read, size_t sector_address, uint16_t offset,
                                          struct norchid_hash_table_entry* hash_table) {
    nor_read(sector_address+offset, (uint8_t*)hash_table, sizeof(*hash_table));
}

static inline void raw_update_hash_table_key(nc_nor_write nor_write, size_t sector_address, uint16_t table_offset,
                                                     size_t index, uint16_t data_offset) {
    nor_write(sector_address+table_offset+sizeof(struct norchid_entry_header)+index*sizeof(uint16_t),
              (const uint8_t*)&data_offset, sizeof(data_offset));
}

// Key entry read/write functions

static inline void raw_read_key_entry(nc_nor_read nor_read, size_t sector_address, uint16_t offset,
                                        struct norchid_key_entry* key) {
    nor_read(sector_address+offset, (uint8_t*)key, sizeof(*key));
}

static inline uint16_t raw_read_key_string(nc_nor_read nor_read, size_t sector_address, uint16_t offset,
                                           const struct norchid_key_entry* entry,
                                           uint8_t* key, size_t max_len) {

    size_t len = entry->key_length;
    if (entry->key_length >= max_len) {
        len = max_len-1;
    }
    nor_read(sector_address+offset+sizeof(struct norchid_key_entry), (uint8_t*)key, len);
    key[len] = '\0';
    return len;
}

static inline void raw_write_key_entry(nc_nor_write nor_write, size_t sector_address, uint16_t offset,
                                          const struct norchid_key_entry *key) {
    nor_write(sector_address+offset, (uint8_t*)key, sizeof(*key));
}

static inline void raw_write_key_string(nc_nor_write nor_write, size_t sector_address, uint16_t offset,
                                                const struct norchid_key_entry *entry, const char *key) {
    nor_write(sector_address+offset+sizeof(struct norchid_key_entry), (uint8_t*)key, entry->key_length);
}

static inline void raw_update_key_entry_next(nc_nor_write nor_write, size_t sector_address, uint16_t offset,
                                                     uint16_t next_offset) {
    const size_t field_offset = 2;
    nor_write(sector_address+offset+field_offset, (const uint8_t*)&next_offset, sizeof(next_offset));
}

static inline void raw_update_key_entry_value(nc_nor_write nor_write, size_t sector_address, uint16_t offset,
                                                     uint16_t value_offset) {
    const size_t field_offset = 4;
    nor_write(sector_address+offset+field_offset, (const uint8_t*)&value_offset, sizeof(value_offset));
}

// Value entry read/write functions

static inline void raw_read_value_entry(nc_nor_read nor_read, size_t sector_address, uint16_t offset,
                                         struct norchid_value_entry* value) {
    nor_read(sector_address+offset, (uint8_t*)value, sizeof(*value));
}

static inline uint16_t raw_read_value_data(nc_nor_read nor_read, size_t sector_address, uint16_t offset,
                                                   const struct norchid_value_entry* entry, uint8_t* value,
                                                           size_t max_len) {
    size_t len = entry->value_length;
    if (entry->value_length >= max_len) {
        len = max_len;
    }
    nor_read(sector_address+offset+sizeof(struct norchid_key_entry), (uint8_t*)value, len);
    return len;
}

static inline void raw_write_value_data(nc_nor_write nor_write, size_t sector_address, uint16_t offset,
                                                const struct norchid_value_entry *entry, const uint8_t *value) {
    nor_write(sector_address+offset+sizeof(struct norchid_key_entry), (uint8_t*)value, entry->value_length);
}

static inline void raw_update_value_entry_next(nc_nor_write nor_write, size_t sector_address, uint16_t offset,
                                                       uint16_t next_offset) {
    const size_t field_offset = 2;
    nor_write(sector_address+offset+field_offset, (const uint8_t*)&next_offset, sizeof(next_offset));
}

// Data comparison on flash-flash or flash-ram
static bool data_is_equal(nc_nor_read nor_read,
                                size_t flash_address_1, const uint8_t *data_1,
                                size_t flash_address_2,
                                size_t len) {
    uint8_t read_data_1[32];
    const uint8_t *data_1_addr;
    uint8_t read_data_2[32];
    for (int i=0; i<len; i+=32) {
        size_t compare_size = len-i >= 32 ? 32 : len-i;

        if (data_1) {
            data_1_addr = data_1 + i;
        } else {
            nor_read(flash_address_1+i, read_data_1, compare_size);
            data_1_addr = read_data_1;
        }

        nor_read(flash_address_2+i, read_data_2, compare_size);

        if (memcmp(data_1_addr, read_data_2, compare_size) != 0) {
            return false;
        }
    }
    return true;
}

static bool ram_equal_to_flash(nc_nor_read nor_read, size_t flash_address, const uint8_t *data, size_t len) {
    return data_is_equal(nor_read, 0, data, flash_address, len);
}

static bool flash_equal_to_flash(nc_nor_read nor_read, size_t flash_address_1, size_t flash_address_2, size_t len) {
    return data_is_equal(nor_read, flash_address_1, NULL, flash_address_2, len);
}

static uint8_t flash_checksum(nc_nor_read nor_read, size_t flash_address, size_t len) {
    uint8_t read_data[32];
    uint8_t crc = 0xFF;
    for (int i=0; i<len; i+=32) {
        size_t crc_size = len-i >= 32 ? 32 : len-i;
        nor_read(flash_address+i, read_data, crc_size);
        crc = norchid_checksum((const char*)read_data, crc_size, crc);
    }
    return crc;
}

static void flash_data_copy(nc_nor_read nor_read, nc_nor_write nor_write, size_t dest_address, size_t source_address, size_t len) {
    uint8_t read_data[32];
    for (int i=0; i<len; i+=32) {
        size_t copy_size = len-i >= 32 ? 32 : len-i;
        nor_read(source_address+i, read_data, copy_size);
        nor_write(dest_address+i, read_data, copy_size);
    }
}


static inline void raw_erase_and_init_sector(nc_nor_erase_sector erase, nc_nor_write write,
                                             size_t sector_start, size_t sector_size, struct norchid_sector_information *info) {

    struct norchid_sector_header header = {
            .magic = "nchd",
            .data_version = 1,
            .status = SECTOR_INITIALIZING,
            .length = sector_size
    };

    erase(sector_start, sector_size);
    raw_write_sector_header(write, sector_start, &header);

    // Write top-level hash table
    struct norchid_entry_header hash_table_header;
    hash_table_header.type = TYPE_HASH_TABLE_ENTRY;
    hash_table_header.status = ENTRY_VALID;

    // Only write header, to leave table blank.
    raw_write_entry_header(write, sector_start, 0, &hash_table_header);

    info->deleted_space = 0;
    info->write_offset = sizeof(struct norchid_sector_header) + sizeof(struct norchid_hash_table_entry);

}

static uint16_t sector_get_first_key_for_crc(nc_nor_read read, size_t sector_base, uint8_t crc) {
    struct norchid_hash_table_entry table;
    read(sector_base + sizeof(struct norchid_sector_header), (uint8_t*)&table, sizeof(struct norchid_hash_table_entry));
    uint16_t offset = table.offsets[crc >> 4];
    if (offset == 0xFFFF) {
        return offset;
    }
    read(sector_base + offset, (uint8_t*)&table, sizeof(struct norchid_hash_table_entry));
    return table.offsets[crc & 0x0F];
}


static uint16_t sector_find_key(nc_nor_read read, size_t sector_base,
                                const char* key, size_t key_flash_address, size_t key_flash_len, uint8_t crc,
                                struct norchid_key_entry *key_entry) {
    uint16_t key_offset = sector_get_first_key_for_crc(read, sector_base, crc);
    size_t key_len;
    if (key) {
        key_len = strlen(key);
    } else {
        key_len = key_flash_len;
    }
    while (key_offset != 0xFFFF) {
        read(sector_base + key_offset, (uint8_t*) key_entry, sizeof(*key_entry));
        if (key_entry->header.status == ENTRY_VALID && key_len == key_entry->key_length) {
            if (key) {
                if (ram_equal_to_flash(read, sector_base + key_offset + sizeof(struct norchid_key_entry),
                                       (const uint8_t*) key, key_len)) {
                    return key_offset;
                }
            } else {
                if (flash_equal_to_flash(read, sector_base + key_offset + sizeof(struct norchid_key_entry),
                                         key_flash_address, key_flash_len)) {
                    return key_offset;
                }
            }
        }
        key_offset = key_entry->next_key_offset;
    }
    return 0xFFFF;
}


static uint16_t sector_find_valid_value(nc_nor_read read, size_t sector_base,
                                        uint16_t first_value_offset,
                                        struct norchid_value_entry *value_entry) {

    uint16_t value_offset = first_value_offset;
    while (value_offset != 0xFFFF) {
        read(sector_base + value_offset, (uint8_t*) &value_entry, sizeof(*value_entry));
        if (value_entry->header.status == ENTRY_VALID) {
            return value_offset;
        }
        value_offset = value_entry->next_value_offset;
    }

    return 0xFFFF;
}

static bool partition_find_key(struct norchid_partition *partition,
                               const char *key, size_t key_flash_address, size_t key_flash_len, uint8_t crc,
                               struct norchid_key_entry *key_entry, uint16_t *key_sector, uint16_t *key_offset) {
    for (int sector=0; sector<partition->params.num_sectors; sector++) {
        uint32_t sector_base = partition->params.base_address + sector*partition->params.sector_size;
        uint16_t offset = sector_find_key(partition->platform.read, sector_base, key, key_flash_address, key_flash_len, crc, key_entry);
        if (offset != 0xFFFF) {
            *key_sector = sector;
            *key_offset = offset;
            return true;
        }
    }
    return false;
}

static bool partition_find_value(struct norchid_partition *partition, const char *key, size_t key_flash_address, size_t key_flash_len, uint8_t crc,
                                 struct norchid_value_entry *value_entry, uint16_t *value_sector, uint16_t *value_offset) {

    struct norchid_key_entry key_entry;
    uint16_t key_offset;
    if (!partition_find_key(partition, key, key_flash_address, key_flash_len, crc, &key_entry, value_sector, &key_offset)) {
        return false;
    }
    uint32_t sector_base = partition->params.base_address + *value_sector*partition->params.sector_size;
    *value_offset = sector_find_valid_value(partition->platform.read, sector_base, key_entry.value_offset, value_entry);
    return *value_offset != 0xFFFF;
}

static bool partition_invalidate_value(struct norchid_partition *partition, const char *key, size_t key_flash_address, size_t key_flash_len, uint8_t crc) {

    struct norchid_value_entry value_entry;
    uint16_t value_sector;
    uint16_t value_offset;

    bool found = partition_find_value(partition, key, key_flash_address, key_flash_len, crc, &value_entry, &value_sector, &value_offset);
    if (found) {
        size_t sector_base = partition->params.base_address + partition->params.sector_size * value_sector;
        raw_update_entry_status(partition->platform.write, sector_base, value_offset, ENTRY_DELETED);
        partition->sector_info[value_sector].deleted_space += sizeof(struct norchid_value_entry) + value_entry.value_length;
    }
    return found;
}

static bool partition_invalidate_key(struct norchid_partition *partition, const char *key, size_t key_flash_address, size_t key_flash_len, uint8_t crc) {

    struct norchid_key_entry key_entry;
    uint16_t key_sector;
    uint16_t key_offset;

    bool found = partition_find_key(partition, key, key_flash_address, key_flash_len, crc, &key_entry, &key_sector, &key_offset);
    if (found) {
        size_t sector_base = partition->params.base_address + partition->params.sector_size * key_sector;
        raw_update_entry_status(partition->platform.write, sector_base, key_offset, ENTRY_DELETED);
        partition->sector_info[key_sector].deleted_space += sizeof(struct norchid_key_entry) + key_entry.key_length;
    }
    return found;
}



static bool norchid_validate_sector_header(struct norchid_partition *partition,
                                           size_t sector) {

    size_t sector_start = partition->params.base_address + sector * partition->params.sector_size;
    struct norchid_sector_header header;
    raw_read_sector_header(partition->platform.read, sector_start, &header);

    // Re-set up sector if we had erased it.
    const uint32_t UNINITIALIZED_FLASH = 0xFFFFFFFF;
    if (memcmp(header.magic, &UNINITIALIZED_FLASH, sizeof(header.magic)) == 0) {

        raw_erase_and_init_sector(partition->platform.erase, partition->platform.write,
                                  sector_start, partition->params.sector_size, &partition->sector_info[sector]);
        raw_update_sector_status(partition->platform.write, sector_start, SECTOR_VALID);
        return true;
    }

    if (memcmp(header.magic, NORCHID_MAGIC, sizeof(header.magic)) != 0) {
        return false;
    }

    if (header.status == SECTOR_BLANK || header.status == SECTOR_INITIALIZING) {
        // We were reorganizing data but didn't finish most likely. We'll need to do that again,
        // but old data is safe.
        raw_erase_and_init_sector(partition->platform.erase, partition->platform.write,
                                  sector_start, partition->params.sector_size, &partition->sector_info[sector]);
        raw_update_sector_status(partition->platform.write, sector_start, SECTOR_VALID);
        return true;
    }

    if (header.status == SECTOR_INITIALIZED) {
        // Reorganizing data finished, but we might not have finished deleting old data.
        if (header.replacing > partition->params.num_sectors) {
            return false;
        }
        size_t replaced_sector_address = header.replacing * partition->params.sector_size + partition->params.base_address;

        raw_erase_and_init_sector(partition->platform.erase, partition->platform.write,
                                  replaced_sector_address, partition->params.sector_size, &partition->sector_info[sector]);
        raw_update_sector_status(partition->platform.write, replaced_sector_address, SECTOR_VALID);

        raw_update_sector_status(partition->platform.write, sector_start, SECTOR_VALID);
        return true;
    }

    if (header.status != SECTOR_VALID) {
        return false;
    }

    if (MIN_DATA_VERSION > header.data_version || MAX_DATA_VERSION < header.data_version) {
        return false;
    }

    return true;
}


enum norchid_status norchid_mount_partition(
        struct norchid_partition *partition,
        const struct norchid_params *params,
        const struct norchid_platform *platform,
        struct norchid_sector_information *sector_info) {

    partition->params = *params;
    partition->platform = *platform;
    partition->sector_info = sector_info;

    if (platform->mutex_lock) {
        bool success = platform->mutex_lock(platform->write_lock, params->max_lock_delay_ms);
        if (!success) {
            return NC_LOCK_TIMEOUT;
        }
    }

    enum norchid_status status = NC_SUCCESS;

    // First check all the sector headers.
    for (int sector=0; sector<params->num_sectors; sector++) {
        if (!norchid_validate_sector_header(partition, sector)) {
            status = NC_INVALID_HEADER;
            goto unlock_and_return;
        }
    }

    // Now, scan through each sector to calculate free space and deleted space cache statistics,
    // and clean up state from in-progress updates.
    for (int sector=0; sector<params->num_sectors; sector++) {
        // Compute header information. To do this, walk through entries in a linear fashion.
        struct norchid_sector_information *this_sector_info = &sector_info[sector];

        this_sector_info->write_offset = 0;
        this_sector_info->deleted_space = 0;

        size_t offset = sizeof(struct norchid_sector_header);
        size_t sector_address = partition->params.base_address + sector * partition->params.sector_size;

        while (offset < partition->params.sector_size) {
            struct norchid_entry_header header;
            raw_read_entry_header(partition->platform.read, sector_address, offset, &header);
            if (header.type == TYPE_EMPTY) {
                break; // No more data
            }

            uint16_t entry_size = 0;
            switch (header.type) {
                case TYPE_HASH_TABLE_ENTRY:
                    entry_size = sizeof(struct norchid_hash_table_entry);
                    break;
                case TYPE_KEY_ENTRY: {
                    struct norchid_key_entry key_entry;
                    raw_read_key_entry(partition->platform.read, sector_address, offset, &key_entry);
                    entry_size = sizeof(key_entry);
                    if (key_entry.key_length != 0xFFFF) {
                        entry_size += key_entry.key_length;
                    }
                    break;
                }
                case TYPE_VALUE_ENTRY: {
                    struct norchid_value_entry value_entry;
                    raw_read_value_entry(partition->platform.read, sector_address, offset, &value_entry);
                    entry_size = sizeof(value_entry);
                    if (value_entry.value_length != 0xFFFF) {
                        entry_size += value_entry.value_length;
                    }
                    break;
                }
                default:
                    status = NC_INVALID_ENTRY;
                    goto unlock_and_return;
            }

            bool is_deleted = header.status == ENTRY_DELETED;

            if (header.status == ENTRY_STARTED) {
                // Entry was not finished. We should automatically delete.
                raw_update_entry_status(partition->platform.write, sector_address, offset, ENTRY_DELETED);
                is_deleted = true;
            } else if (header.status == ENTRY_WRITTEN) {
                // Entry was written, but we need to search for outdated values that need to be deleted.
                struct norchid_key_entry key_entry;
                raw_read_key_entry(partition->platform.read, sector_address, offset, &key_entry);
                uint8_t crc = flash_checksum(partition->platform.read, sector_address + offset + sizeof(struct norchid_key_entry), key_entry.key_length);

                if (header.type == TYPE_KEY_ENTRY) {
                    // (1) invalidate old value, if exists.
                    partition_invalidate_value(partition, NULL, sector_address+offset, key_entry.key_length, crc);
                    // (2) invalidate old key, if exists
                    partition_invalidate_key(partition, NULL, sector_address+offset, key_entry.key_length, crc);
                    // (3) validate new value. Value data will be correct before key is listed as valid
                    raw_update_entry_status(partition->platform.write, sector_address, key_entry.value_offset, ENTRY_VALID);
                    // (4) validate new key
                    raw_update_entry_status(partition->platform.write, sector_address, offset, ENTRY_VALID);
                } else if (header.type == TYPE_VALUE_ENTRY) {
                    // If this is a value entry, the key is already valid and should not be changed. We should:
                    // (1) invalidate old value, if exists.
                    partition_invalidate_value(partition, NULL, sector_address+offset, key_entry.key_length, crc);
                    // (2) validate new value.
                    raw_update_entry_status(partition->platform.write, sector_address, offset, ENTRY_VALID);
                }
            }
            if (is_deleted) {
                this_sector_info->deleted_space += entry_size;
            }
            offset += entry_size;
        }
        this_sector_info->write_offset = offset;
    }


unlock_and_return:
    if (platform->mutex_unlock) {
        platform->mutex_unlock(platform->write_lock);
    }

    return status;
}


enum norchid_status norchid_format_partition(struct norchid_partition *partition) {

    if (partition->platform.mutex_lock) {
        bool success = partition->platform.mutex_lock(partition->platform.mutex_lock,
                                                    partition->params.max_lock_delay_ms);
        if (!success) {
            return NC_LOCK_TIMEOUT;
        }
    }

    for (int sector=0; sector<partition->params.num_sectors; sector++) {
        size_t sector_base = partition->params.base_address + sector * partition->params.sector_size;
        raw_erase_and_init_sector(partition->platform.erase, partition->platform.write,
                                  sector_base, partition->params.sector_size, &partition->sector_info[sector]);
        raw_update_sector_status(partition->platform.write, sector_base, SECTOR_VALID);
    }

    if (partition->platform.mutex_unlock) {
        partition->platform.mutex_unlock(partition->platform.write_lock);
    }

    return NC_SUCCESS;
}



enum norchid_status norchid_put_integer(
        struct norchid_partition *partition,
        const char* key,
        int value) {
    return norchid_put_binary(partition, key, (const uint8_t*) &value, sizeof(int));
}

enum norchid_status norchid_put_string(
        struct norchid_partition *partition,
        const char* key,
        const char* value) {
    return norchid_put_binary(partition, key, (const uint8_t*) value, strlen(key));
}

enum norchid_status norchid_put_binary(
        struct norchid_partition *partition,
        const char *key,
        const uint8_t *value,
        size_t len) {

    // Find existing key and value, if it exists.
    int current_sector;
    int current_offset;
    for (current_sector=0; current_sector<partition->params.num_sectors; current_sector++) {
        current_offset = 0;
    }

    //TODO
    // If we can extend the value chain, we can just write the value. Figure out if we can do that.

    // Change sector if needed

    // Write key (if needed)

    // Write value ()

    // Invalidate old value

    // Invalidate old key (if needed)

    // Validate new value

    // validate new key

}

enum norchid_status norchid_get_integer(
        struct norchid_partition *partition,
        const char* key,
        int* value) {
    return norchid_get_binary(partition, key, (uint8_t*) value, sizeof(int), NULL);
}

enum norchid_status norchid_get_string(
        struct norchid_partition *partition,
        const char* key,
        char* value,
        size_t max_len,
        size_t* len) {
    enum norchid_status status = norchid_get_binary(partition, key, (uint8_t*) value, max_len-1, len);
    value[*len] = '\0';
    return status;
}

enum norchid_status norchid_get_binary(
        struct norchid_partition *partition,
        const char* key,
        uint8_t* value,
        size_t max_len,
        size_t* len) {

    size_t key_len = strlen(key);
    uint8_t crc = norchid_checksum(key, key_len, 0xFF);

    struct norchid_value_entry value_entry;
    uint16_t value_sector;
    uint16_t value_offset;

    bool success = partition_find_value(partition, key, 0, 0, norchid_checksum(key, strlen(key), crc), &value_entry, &value_sector, &value_offset);
    if (!success) {
        return NC_NOT_FOUND;
    }

    size_t sector_base = partition->params.num_sectors * value_sector;
    uint16_t bytes_read = raw_read_value_data(partition->platform.read, sector_base, value_offset, &value_entry, value, max_len);
    *len = bytes_read;

    return (bytes_read == value_entry.value_length ? NC_SUCCESS : NC_TRUNCATED);
}

enum norchid_status norchid_exists(
        struct norchid_partition *partition,
        const char *key) {

    size_t key_len = strlen(key);
    uint8_t crc = norchid_checksum(key, key_len, 0xFF);
    struct norchid_value_entry value_entry;
    uint16_t sector, offset;
    return partition_find_value(partition, key, 0, 0, crc, &value_entry, &sector, &offset) ? NC_SUCCESS : NC_NOT_FOUND;

}

enum norchid_status norchid_open_list(
        struct norchid_partition *partition,
        struct norchid_iterator *iterator) {

    enum norchid_status status = NC_SUCCESS;
    if (partition->platform.mutex_lock) {
        status = partition->platform.mutex_lock(partition->platform.write_lock, partition->params.max_lock_delay_ms);
    }

    iterator->current_sector = 0;
    iterator->current_entry_offset = sizeof(struct norchid_sector_header);
    iterator->partition = partition;
    return status;
}

enum norchid_status norchid_next_key(
        struct norchid_iterator *iterator,
        char* key, size_t max_len, size_t* len) {

    struct norchid_partition *partition = iterator->partition;

    while (iterator->current_sector < partition->params.num_sectors) {
        size_t sector_base = partition->params.base_address + iterator->current_sector * partition->params.sector_size;
        // Read entry header
        struct norchid_entry_header entry_header;
        raw_read_entry_header(partition->platform.read, sector_base, iterator->current_entry_offset, &entry_header);

        // If unwritten: Go to next sector, reset offset, continue.
        if (entry_header.status == ENTRY_BLANK) {

            iterator->current_sector += 1;
            iterator->current_entry_offset = sizeof(struct norchid_sector_header);
            continue;
        }

        // Find entry size, add to offset.
        uint16_t entry_size;
        struct norchid_key_entry key_entry = {0};
        uint16_t entry_offset = iterator->current_entry_offset;
        switch (entry_header.type) {
            case TYPE_VALUE_ENTRY: {
                struct norchid_value_entry value_entry;
                entry_size = sizeof(struct norchid_value_entry);
                raw_read_value_entry(partition->platform.read, sector_base, entry_offset, &value_entry);
                entry_size += value_entry.value_length;
            }
                break;
            case TYPE_KEY_ENTRY: {
                entry_size = sizeof(struct norchid_key_entry);
                raw_read_key_entry(partition->platform.read, sector_base, entry_offset, &key_entry);
                entry_size += key_entry.key_length;
            }
                break;
            case TYPE_HASH_TABLE_ENTRY:
                entry_size = sizeof(struct norchid_hash_table_entry);
                break;
            default:
                return NC_ERROR_INTERNAL;
        }
        iterator->current_entry_offset += entry_size;

        if (iterator->current_entry_offset >= partition->params.sector_size - sizeof(struct norchid_entry_header)) {
            iterator->current_sector += 1;
            iterator->current_entry_offset = sizeof(struct norchid_sector_header);
        }

        // If a key and valid: Extract the key and return!
        if (entry_header.status == ENTRY_VALID && entry_header.type == TYPE_KEY_ENTRY) {
            *len = raw_read_key_string(partition->platform.read, sector_base, entry_offset, &key_entry, (uint8_t*)key, max_len-1);
            key[*len] = '\0';
        }

        return (max_len-1 == *len) ? NC_SUCCESS : NC_TRUNCATED;

    }

    return NC_NOT_FOUND;
}

enum norchid_status norchid_close_list(
        struct norchid_iterator *iterator) {

    struct norchid_platform *platform = &iterator->partition->platform;

    if (platform->mutex_unlock) {
        platform->mutex_unlock(platform->write_lock);
    }

    return NC_SUCCESS;
}

enum norchid_status norchid_cleanup(
        struct norchid_partition *partition) {


    enum norchid_status status = NC_SUCCESS;
    if (partition->platform.mutex_lock) {
        status = partition->platform.mutex_lock(partition->platform.write_lock, partition->params.max_lock_delay_ms);
        if (status != NC_SUCCESS) {
            return status;
        }
    }

    // Identify the sector to clean up first.
    uint16_t sector_to_clean = 0;
    uint16_t freed_space = 0;
    for (int sector=0; sector<partition->params.num_sectors; sector++) {
        if (partition->sector_info[sector].deleted_space > freed_space) {
            freed_space = partition->sector_info[sector].deleted_space;
            sector_to_clean = sector;
        }
    }

    // Clean into the next free sector (wrapping around)
    uint16_t destination_sector = sector_to_clean;
    for (int i=0; i<partition->params.num_sectors-1; i++) {
        destination_sector++;
        if (destination_sector >= partition->params.num_sectors) {
            destination_sector -= partition->params.num_sectors;
        }
        if (partition->sector_info->write_offset == sizeof(struct norchid_sector_header)) {
            break;
        }
    }

    if (destination_sector == sector_to_clean) {
        // This shouldn't happen, we should prevent ourselves from using all sectors.
        status = NC_ERROR_INTERNAL;
        goto unlock_and_return;
    }

    // TODO mark new sector as replacing the old sector?


    // Migrate things over by CRC
    uint16_t *write_offset = &partition->sector_info->write_offset;

    struct norchid_hash_table_entry src_root_table;
    struct norchid_hash_table_entry dest_root_table;
    memset(&dest_root_table, 0xFF, sizeof(dest_root_table));
    raw_read_hash_table_entry(partition->platform.read, SECTOR_ADDR(partition, sector_to_clean),
                              sizeof(struct norchid_sector_header), &src_root_table);

    for (int t1_i=0; t1_i<HASH_TABLE_BIN_COUNT; t1_i++) {

        bool wrote_second_level_table = false;

        if (src_root_table.offsets[t1_i] == 0xFFFF) {
            continue;
        }
        struct norchid_hash_table_entry second_level_table;
        raw_read_hash_table_entry(partition->platform.read, SECTOR_ADDR(partition, sector_to_clean),
                                  src_root_table.offsets[t1_i], &second_level_table);
        if (second_level_table.header.status != ENTRY_VALID) {
            continue;
        }

        for (int t2_i=0; t2_i<HASH_TABLE_BIN_COUNT; t2_i++) {

            uint16_t src_key_offset = second_level_table.offsets[t2_i];
            while (src_key_offset != 0xFFFF) {
                struct norchid_key_entry key_entry;
                raw_read_key_entry(partition->platform.read, SECTOR_ADDR(partition, sector_to_clean), src_key_offset,
                                   &key_entry);
                if (key_entry.header.status == ENTRY_VALID) {

                    uint16_t src_value_offset = key_entry.value_offset;
                    while (src_value_offset != 0xFFFF) {
                        struct norchid_value_entry value_entry;
                        raw_read_value_entry(partition->platform.read, SECTOR_ADDR(partition, sector_to_clean), src_value_offset,
                                             &value_entry);

                        src_value_offset = value_entry.next_value_offset;
                        if (value_entry.header.status == ENTRY_VALID) {

                            // Write 2nd level table if we haven't
                            if (!wrote_second_level_table) {
                                struct norchid_hash_table_entry new_table;
                                memset(&new_table, 0xFF, sizeof(dest_root_table));
                                new_table.header.type = TYPE_HASH_TABLE_ENTRY;
                                new_table.header.status = ENTRY_WRITTEN;

                                uint16_t new_table_offset = partition->sector_info[destination_sector].write_offset;
                                raw_write_entry_header(partition->platform.write, SECTOR_ADDR(partition, destination_sector), new_table_offset,
                                                       &new_table.header);
                                partition->sector_info[destination_sector].write_offset += sizeof(struct norchid_hash_table_entry);
                                raw_update_hash_table_key(partition->platform.write, SECTOR_ADDR(partition, destination_sector),
                                                          sizeof(struct norchid_sector_header), destination_sector, new_table_offset);
                                raw_update_entry_status(partition->platform.write, SECTOR_ADDR(partition, destination_sector), new_table_offset,
                                                        ENTRY_VALID);
                            }


                            // Write new key:value we found // TODO

                            uint16_t new_key_offset = partition->sector_info[destination_sector].write_offset;
                            uint16_t new_value_offset = new_key_offset + sizeof(struct norchid_key_entry) + key_entry.key_length;

                            struct norchid_key_entry new_key = key_entry;
                            struct norchid_value_entry new_value = value_entry;

                            new_key.value_offset = 0xFFFF;
                            new_key.next_key_offset = 0xFFFF;
                            new_key.header.status = ENTRY_STARTED;

                            new_value.next_value_offset = 0xFFFF;
                            new_value.header.status = ENTRY_STARTED;

                            // Find out where to update header (2nd level table or follow to newest key)

                            // Write key

                            // Write value

                            // Update value (written)

                            // Update key (written)

                            // Update header/link location

                            // Update key (valid)

                            // Update value (valid)


                            break;
                        }
                    }
                }

                src_key_offset = key_entry.next_key_offset;
            }
        }
    }

unlock_and_return:
    if (partition->platform.mutex_unlock) {
        partition->platform.mutex_unlock(partition->platform.write_lock);
    }

    return status;
}