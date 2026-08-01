#pragma once

#include <cstddef>
#include <cstdint>

// Minimal Android 13 libcamera_metadata C ABI used by this provider. Keeping the
// declarations local avoids depending on platform-private headers while the
// checked-copy entry point makes serialized AIDL metadata safe to inspect.
extern "C" {

struct camera_metadata;
typedef struct camera_metadata camera_metadata_t;

typedef struct camera_metadata_rational {
    int32_t numerator;
    int32_t denominator;
} camera_metadata_rational_t;

enum camera_metadata_type : uint8_t {
    CAMERA_METADATA_TYPE_BYTE = 0,
    CAMERA_METADATA_TYPE_INT32 = 1,
    CAMERA_METADATA_TYPE_FLOAT = 2,
    CAMERA_METADATA_TYPE_INT64 = 3,
    CAMERA_METADATA_TYPE_DOUBLE = 4,
    CAMERA_METADATA_TYPE_RATIONAL = 5,
    CAMERA_METADATA_NUM_TYPES = 6,
};

typedef struct camera_metadata_ro_entry {
    size_t index;
    uint32_t tag;
    uint8_t type;
    size_t count;
    union {
        const uint8_t* u8;
        const int32_t* i32;
        const float* f;
        const int64_t* i64;
        const double* d;
        const camera_metadata_rational_t* r;
    } data;
} camera_metadata_ro_entry_t;

camera_metadata_t* allocate_camera_metadata(size_t entry_capacity, size_t data_capacity);
camera_metadata_t* allocate_copy_camera_metadata_checked(
        const camera_metadata_t* source, size_t source_size);
camera_metadata_t* clone_camera_metadata(const camera_metadata_t* source);
void free_camera_metadata(camera_metadata_t* metadata);

int add_camera_metadata_entry(camera_metadata_t* destination, uint32_t tag,
                              const void* data, size_t data_count);
int sort_camera_metadata(camera_metadata_t* metadata);
int get_camera_metadata_ro_entry(const camera_metadata_t* source, size_t index,
                                 camera_metadata_ro_entry_t* entry);
int find_camera_metadata_ro_entry(const camera_metadata_t* source, uint32_t tag,
                                  camera_metadata_ro_entry_t* entry);

size_t get_camera_metadata_size(const camera_metadata_t* metadata);
size_t get_camera_metadata_compact_size(const camera_metadata_t* metadata);
size_t get_camera_metadata_entry_count(const camera_metadata_t* metadata);
int get_camera_metadata_tag_type(uint32_t tag);
int validate_camera_metadata_structure(const camera_metadata_t* metadata,
                                       const size_t* expected_size);

}  // extern "C"

static_assert(sizeof(void*) == 8, "libcamera_metadata wrapper requires the 64-bit image ABI");
static_assert(sizeof(camera_metadata_rational_t) == 8);
static_assert(offsetof(camera_metadata_ro_entry_t, index) == 0);
static_assert(offsetof(camera_metadata_ro_entry_t, tag) == 8);
static_assert(offsetof(camera_metadata_ro_entry_t, type) == 12);
static_assert(offsetof(camera_metadata_ro_entry_t, count) == 16);
static_assert(offsetof(camera_metadata_ro_entry_t, data) == 24);
static_assert(sizeof(camera_metadata_ro_entry_t) == 32);
