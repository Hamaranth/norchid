# norchid

`norchid` is a nonvolatile dictionary implemented using raw NOR flash as storage.

It's key design goals are:

* a lightweight memory footprint
* data safety and consistency, so crashes and power failures don't cause data loss
* write-efficiency
* an understandable design and codebase

This makes it useful in small systems where you may want a generic storage mechanism,
but either lack or don't wish to commit the resources to a full filesystem.

`norchid` targets NOR flash specifically because it's a popular form of storage in
microcontroller-based systems. Many parts require use of an external NOR flash
to store the program on it, and give you the capability to use a different
section of the flash for data storage. 

# Usage

Add `norchid.c` and `norchid.h` to your project's build system!

## Mounting and Setup

To use `norchid`, you'll need to give it a few things:

* Some driver functions to use to interact with your nor flash. This corresponds to 
  the `norchid_platform` structure.
    * If you're using `norchid` in a single-threaded manner, you just need to provide
      the `write`, `read`, and `erase` functions and set the other functions to `NULL`. 
    * If you are accessing `norchid` from independent threads, you'll want to implement
      the `mutex_lock` and `mutex_unlock` functions (along with setting `write_lock` to
      a lock handle, if necessary).
* Some parameters to tell `norchid` about the region where you want to store data. These
  parameters are in the `norchid_params` structure.
    * `base_address` is the start of the area you want to use for `norchid` data.
    * `sector_size` is the size of the erasable region of your NOR flash.
    * `num_sectors` is the number of sectors you wish to use for `norchid` data. You must
      use at least two.
* A little bit of RAM for each sector `norchid` manages (4 bytes each).
    * You'll need an array `norchid_sector_information` structures, of size `num_sectors`.

TODO: add example usage

# Flash Storage Format

`norchid` treats all sectors within a partition with the same format. One sector is
reserved as unused/free space at all times, to have space to work with in case data 
needs to be organized or re-ordered.

Numbers are stored in the platform's native representation/endianness.

Sectors have the following header information at their start:

| Name          | Size    | Description                                                          |
|---------------|---------|----------------------------------------------------------------------|
| Magic         | 4 bytes | Characters 'nchd'                                                    |
| Data Version  | 1 byte  | Version of data stored in this partition (0x01)                      |
| Status        | 1 byte  | Sector status                                                        |
 | Sector Length | 2 bytes | Sector size (Usually 2048 or 4096, but can be multiples up to 65536) |
| Replacing     | 2 bytes | Used to temporarily store which sector this sector replaces          |

Immediately after the sector header, there is a 16-element hash table. Each offset is a 16-bit
value. The most significant 4 bits of the CRC-8 of the key is used to determine the hash index to follow.
If there are no keys there, the value is unwritten (0xFFFF).

Hash table entries have the following format:

| Name           | Size       | Description                          |
|----------------|------------|--------------------------------------|
| Type           | 1 byte     | Entry type                           |
| Status         | 1 byte     | Entry status                         |
| Offsets        | 2*16 bytes | Offset of next table entries or keys |

These offsets point toward a second-level hash table, these using the least significant bits of the CRC.
The offsets in the second-level tables point to the first maching key entry.

Key entries have the following format:

| Name            | Size    | Description                           |
|-----------------|---------|---------------------------------------|
| Type            | 1 byte  | Entry type                            |
| Status          | 1 byte  | Entry status                          |
| Next Key Offset | 2 bytes | Offset of next key with matching hash |
| Value Offset    | 2 bytes | Location of value entry               |
| Key Length      | 2 bytes | Length of key                         |
 | Key             | n bytes | Key data (without NULL terminator)    |

Value entries are similarly formatted:

| Name              | Size    | Description          |
|-------------------|---------|----------------------|
| Type              | 1 byte  | Entry type           |
| Status            | 1 byte  | Entry status         |
| Next Value Offset | 2 bytes | Offset of next value |
| Value Length      | 2 bytes | Length of value      |
| Value             | n bytes | Value data           |
