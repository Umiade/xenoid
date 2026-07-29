/**
 * Copyright (c) 2019,libgralloctypes_helper The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.hardware.graphics.common;

/**
 * Used by IAllocator/IMapper (gralloc) to describe standard metadata types.
 *
 * This is an enum that defines the common types of gralloc 4 buffer metadata. The comments for
 * each enum include a description of the metadata that is associated with the type.
 *
 * IMapper@4.x must support getting the following standard buffer metadata types, with the exception
 * of SMPTE 2094-10 metadata. IMapper@4.x may support setting these standard buffer metadata types
 * as well.
 *
 * When encoding these StandardMetadataTypes into a byte stream, the associated MetadataType is
 * is first encoded followed by the StandardMetadataType value. The MetadataType is encoded by
 * writing the length of MetadataType.name using 8 bytes in little endian, followed by a char
 * array of MetadataType.name's characters. The char array is not null terminated. Finally,
 * MetadataType.value is represented by 8 bytes written in little endian.
 *
 * The StandardMetadataType encode/decode support library can be found in:
 * frameworks/native/libs/gralloc/types/include/gralloctypes/Gralloc4.h.
 * @hide
 */
@VintfStability
@Backing(type="long")
enum StandardMetadataType {
    INVALID = 0,

    /**
     * Can be used to get the random ID of the buffer. This ID should be psuedorandom with
     * sufficient entropy.
     *
     * This ID should only be used for debugging purposes. It cannot be used as a basis for any
     * control flows.
     *
     * The buffer ID is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The buffer ID is a uint64_t.
     *
     * When it is encoded into a byte stream, it is represented by 8 bytes written in little endian.
     */
    BUFFER_ID = 1,

    /**
     * Can be used to get the name passed in by the client at allocation time in the
     * BufferDescriptorInfo.
     *
     * The buffer name is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The buffer name is a string.
     *
     * When it is encoded into a byte stream, the length of the string is written using 8 bytes in
     * little endian. It is followed by a char array of the string's
     * characters. The array is not null-terminated.
     */
    NAME = 2,

    /**
     * Can be used to get the number of elements per buffer row requested at allocation time in
     * the BufferDescriptorInfo.
     *
     * The width is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The width is a uint64_t.
     *
     * When it is encoded into a byte stream, it is represented by 8 bytes written in little endian.
     */
    WIDTH = 3,

    /**
     * Can be used to get the number of elements per buffer column requested at allocation time in
     * the BufferDescriptorInfo.
     *
     * The height is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The height is a uint64_t.
     *
     * When it is encoded into a byte stream, it is represented by 8 bytes written in little endian.
     */
    HEIGHT = 4,

    /**
     * Can be used to get the number of layers requested at allocation time in the
     * BufferDescriptorInfo.
     *
     * The layer count is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The layer count is a uint64_t.
     *
     * When it is encoded into a byte stream, it is represented by 8 bytes written in little endian.
     */
    LAYER_COUNT = 5,

    /**
     * Can be used to get the buffer format requested at allocation time in the
     * BufferDescriptorInfo.
     *
     * The requested pixel format is determined at allocation time and should not change during
     * the lifetime of the buffer.
     *
     * The requested pixel format is a android.hardware.graphics.common@1.2::PixelFormat.
     *
     * When it is encoded into a byte stream, it is first cast to a int32_t and then represented in
     * the byte stream by 4 bytes written in little endian.
     */
    PIXEL_FORMAT_REQUESTED = 6,

    /**
     * Can be used to get the fourcc code for the format. Fourcc codes are standard across all
     * devices of the same kernel version. Fourcc codes must follow the Linux definition of a
     * fourcc format found in: include/uapi/drm/drm_fourcc.h.
     *
     * The pixel format fourcc code is represented by a uint32_t.
     *
     * When it is encoded into a byte stream, it is represented by 4 bytes written in little endian.
     */
    PIXEL_FORMAT_FOURCC = 7,

    /**
     * Can be used to get the modifier for the format. Together fourcc and modifier describe the
     * real pixel format. Each fourcc and modifier pair is unique and must fully define the format
     * and layout of the buffer. Modifiers can change any property of the buffer. Modifiers must
     * follow the Linux definition of a modifier found in: include/uapi/drm/drm_fourcc.h.
     *
     * The pixel format modifier is represented by a uint64_t.
     *
     * When it is encoded into a byte stream, it is represented by 8 bytes written in little endian.
     */
    PIXEL_FORMAT_MODIFIER = 8,

    /**
     * Can be used to get the usage requested at allocation time in the BufferDescriptorInfo.
     *
     * The usage is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The usage is a uint64_t bit field of android.hardware.graphics.common@1.2::BufferUsage's.
     *
     * When it is encoded into a byte stream, it is represented by 8 bytes written in little endian.
     */
    USAGE = 9,

    /**
     * Can be used to get the total size in bytes of any memory used by the buffer including its
     * metadata and extra padding. This is the total number of bytes used by the buffer allocation.
     *
     * The allocation size is a uint64_t.
     *
     * When it is encoded into a byte stream, it is represented by 8 bytes written in little endian.
     */
    ALLOCATION_SIZE = 10,

    /**
     * Can be used to get if a buffer has protected content. If the buffer does not have protected
     * content, this should return 0. If a buffer has protected content, this should return 1.
     *
     * In future versions, this field will be extended to expose more information about the type
     * of protected content in the buffer.
     *
     * The protected content is a uint64_t.
     *
     * When it is encoded into a byte stream, it is represented by 8 bytes written in little endian.
     */
    PROTECTED_CONTENT = 11,

    /**
     * Can be used to get the compression strategy of the buffer. If the device has more than one
     * compression strategy, it should have different unique values for each compression
     * strategy.
     *
     * Compression is a stable aidl android.hardware.graphics.common.ExtendableType.
     *
     * android.hardware.graphics.common.Compression defines the standard compression
     * strategies. Vendors may extend this type to include any compression strategies.
     *
     * When it is encoded into a byte stream, the length of the name field string is written using
     * 8 bytes in little endian. It is followed by a char array of the string's
     * characters. The array is not null-terminated. Finally the value field is written as 8 bytes
     * in little endian.
     */
    COMPRESSION = 12,

    /**
     * Can be used to get how the buffer's planes are interlaced.
     *
     * Interlaced is a stable aidl android.hardware.graphics.common.ExtendableType.
     *
     * android.hardware.graphics.common.Interlaced defines the standard interlaced
     * strategies. Vendors may extend this type to include any non-standard interlaced
     * strategies.
     *
     * When it is encoded into a byte stream, the length of the name field string is written using
     * 8 bytes in little endian. It is followed by a char array of the string's
     * characters. The array is not null-terminated. Finally the value field is written as 8 bytes
     * in little endian.
     */
    INTERLACED = 13,

    /**
     * Can be used to get the chroma siting of a buffer.
     *
     * Chroma siting is a stable aidl android.hardware.graphics.common.ExtendableType.
     *
     * android.hardware.graphics.common.ChromaSiting defines the standard chroma
     * sitings. Vendors may extend this type to include any non-standard chroma sitings.
     *
     * When it is encoded into a byte stream, the length of the name field string is written using
     * 8 bytes in little endian. It is followed by a char array of the string's
     * characters. The array is not null-terminated. Finally the value field is written as 8 bytes
     * in little endian.
     */
    CHROMA_SITING = 14,

    /**
     * Can be used to get the PlaneLayout(s) of the buffer. There should be one PlaneLayout per
     * plane in the buffer. For example if the buffer only has one plane, only one PlaneLayout
     * should be returned.
     *
     * If the buffer has planes interlaced through time, the returned PlaneLayout structs should be
     * ordered by time. The nth PlaneLayout should be from the same time or earlier than the
     * n+1 PlaneLayout.
     *
     * The plane layout is a list of stable aidl android.hardware.graphics.common.PlaneLayout's.
     *
     * When it is encoded into a byte stream, the total number of PlaneLayouts is written using
     * 8 bytes in little endian. It is followed by each PlaneLayout.
     *
     * To encode a PlaneLayout, write the length of its PlaneLayoutComponent[] components
     * field as 8 bytes in little endian and then encode each of its components. Finally, write the
     * following fields in this order each as 8 bytes in little endian: offsetInBytes,
     * sampleIncrementInBits, strideInBytes, widthInSamples, totalSizeInBytes,
     * horizontalSubsampling, verticalSubsampling.
     *
     * To encode a PlaneLayoutComponent, encode its PlaneLayoutComponentType type field. Next
     * encode offsetInBits followed by sizeInBits each as 8 bytes in little endian.
     *
     * To encode a PlaneLayoutComponentType, write the length of the name field string as
     * 8 bytes in little endian. It is followed by a char array of the string's
     * characters. The array is not null-terminated. Finally the value field is written as 8 bytes
     * in little endian.
     */
    PLANE_LAYOUTS = 15,

    /**
     * Can be used to get the crop of the buffer.
     *
     * Some buffer producers require extra padding to their output buffer; therefore the
     * physical size of the native buffer will be larger than its logical size.
     * The crop rectangle(s) determine the offset and logical size of the buffer that should be
     * read by consumers.
     *
     * The crop is defined per plane. The crop(s) are represented by an array of
     * android.hardware.graphics.common.Rects. The array must be the same length and in the same
     * order as the array of PlaneLayouts. Eg. the first crop in the array is the crop for the
     * first PlaneLayout in the PlaneLayout array.
     *
     * Each crop Rect is measured in samples and is relative to the offset of the plane. Valid crop
     * rectangles are within the boundaries of the plane: [0, 0, widthInSamples, heightInSamples].
     * The default crop rectangle of each plane is a rectangle the same size as the plane:
     * [0, 0, widthInSamples, heightInSamples].
     *
     * When it is encoded into a byte stream, the total number of Rects is written using
     * 8 bytes in little endian. It is followed by each Rect.
     *
     * To encode a Rect, write the following fields in this order each as 8 bytes in little endian:
     * left, top, right and bottom.
     */
    CROP = 16,

    /**
     * Can be used to get or set the dataspace of the buffer. The framework may attempt to set
     * this value.
     *
     * The default dataspace is Dataspace::UNKNOWN. If this dataspace is set to any valid value
     * other than Dataspace::UNKNOWN, this dataspace overrides all other dataspaces. For example,
     * if the buffer has Dataspace::DISPLAY_P3 and it is being displayed on a composer Layer that
     * is Dataspace::sRGB, the buffer should be treated as a DISPLAY_P3 buffer.
     *
     * The dataspace is a stable aidl android.hardware.graphics.common.Dataspace.
     *
     * When it is encoded into a byte stream, it is first cast to a int32_t and then represented in
     * the byte stream by 4 bytes written in little endian.
     */
    DATASPACE = 17,

    /**
     * Can be used to get or set the BlendMode. The framework may attempt to set this value.
     *
     * The default blend mode is INVALID. If the BlendMode is set to any
     * valid value other than INVALID, this BlendMode overrides all other
     * blend modes. For a longer description of this behavior see MetadataType::DATASPACE.
     *
     * The blend mode is a stable aidl android.hardware.graphics.common.BlendMode.
     *
     * When it is encoded into a byte stream, it is first cast to a int32_t and then represented by
     * 4 bytes written in little endian.
     */
    BLEND_MODE = 18,

    /**
     * Can be used to get or set static HDR metadata specified by SMPTE ST 2086.
     *
     * This metadata is a stable aidl android.hardware.graphics.common.Smpte2086.
     *
     * This is not used in tone mapping until it has been set for the first time.
     *
     * When it is encoded into a byte stream, each float member is represented by 4 bytes written in
     * little endian. The ordering of float values follows the definition of Smpte2086 and XyColor.
     * If this is unset when encoded into a byte stream, the byte stream is empty.
     */
    SMPTE2086 = 19,

    /**
     * Can be used to get or set static HDR metadata specified by CTA 861.3.
     *
     * This metadata is a stable aidl android.hardware.graphics.common.Cta861_3.
     *
     * This is not used in tone mapping until it has been set for the first time.
     *
     * When it is encoded into a byte stream, each float member is represented by 4 bytes written in
     * little endian. The ordering of float values follows the definition of Cta861_3.
     * If this is unset when encoded into a byte stream, the byte stream is empty.
     */
    CTA861_3 = 20,

    /**
     * Can be used to get or set dynamic HDR metadata specified by SMPTE ST 2094-40:2016.
     *
     * This metadata is a uint8_t byte array.
     *
     * This is not used in tone mapping until it has been set for the first time.
     *
     * When it is encoded into a byte stream, the length of the HDR metadata byte array is written
     * using 8 bytes in little endian. It is followed by the uint8_t byte array.
     * If this is unset when encoded into a byte stream, the byte stream is empty.
     */
    SMPTE2094_40 = 21,

    /**
     * Can be used to get or set dynamic HDR metadata specified by SMPTE ST 2094-10:2016.
     *
     * This metadata is a uint8_t byte array.
     *
     * This is not used in tone mapping until it has been set for the first time.
     *
     * When it is encoded into a byte stream, the length of the HDR metadata byte array is written
     * using 8 bytes in little endian. It is followed by the uint8_t byte array.
     * If this is unset when encoded into a byte stream, the byte stream is empty.
     */
    SMPTE2094_10 = 22,
}
