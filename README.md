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
* A little bit of RAM for each sector `norchid` manages (~8 bytes each).
    * You'll need an array `norchid_sector_information` structures, of size `num_sectors`.



# Flash Storage Format

`norchid` treats all sectors within a partition with the same format. One sector is
reserved as unused/free space at all times, to have space to work with in case data 
needs to be organized or re-ordered.

Numbers are stored in the platform's native representation/endianness.

Sectors have the following header information at their start:

| Name          | Size   | Description                                                        |
|---------------|--------|--------------------------------------------------------------------|
| Magic         | 4 bytes | Characters 'nchd'                                                  |
| Data Version  | 1 byte | Version of data stored in this partition (0x01)                    |
| Status        | 1 byte | Sector status |
 | Sector Length | 2 bytes | Sector size (Usually 2048 or 4096, but can be multiples)           |

The rest of the sector space is reserved to storage. Entry metadata gets stored
after the header, growing forward in the address space, and entry data itself gets
stored at the end of the sector, extending backward.

Entry metadata has the format:

| Name         | Size   | Description                      |
|--------------|--------|----------------------------------|
| Status       | 1 byte | Entry status                     |
| Key Checksum | 1 byte | Checksum of key                  |
 | Key Offset | 2 bytes | Location of key data in sector   |
| Value Offset | 2 bytes | Location of value data in sector |

The corresponding keys and values are written in the following way:

| Name         | Size   | Description     |
|--------------|--------|-----------------|
| Length       | 2 bytes | Length of data  |
| Data | Length bytes | Key or value |
