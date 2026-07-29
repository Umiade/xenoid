/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.hardware.camera.device;

/**
 * CameraBlob:
 *
 * Transport header for camera blob types; generally compressed JPEG buffers in
 * output streams.
 *
 * To capture JPEG images, a stream is created using the pixel format
 * HAL_PIXEL_FORMAT_BLOB and dataspace HAL_DATASPACE_V0_JFIF. The buffer size
 * for the stream is calculated by the framework, based on the static metadata
 * field android.jpeg.maxSize. Since compressed JPEG images are of variable
 * size, the HAL needs to include the final size of the compressed image using
 * this structure inside the output stream buffer. The camera blob ID field must
 * be set to CameraBlobId::JPEG.
 *
 * The transport header must be at the end of the JPEG output stream
 * buffer. That means the jpegBlobId must start at byte[buffer_size -
 * sizeof(CameraBlob)], where the buffer_size is the size of gralloc
 * buffer. Any HAL using this transport header must account for it in
 * android.jpeg.maxSize. The JPEG data itself starts at the beginning of the
 * buffer and must be blobSize bytes long.
 *
 * It also supports transport of JPEG APP segments blob, which contains JPEG APP1 to
 * APPn (Application Marker) segments as specified in JEITA CP-3451.
 *
 * To capture a JPEG APP segments blob, a stream is created using the pixel format
 * HAL_PIXEL_FORMAT_BLOB and dataspace HAL_DATASPACE_JPEG_APP_SEGMENTS. The buffer
 * size for the stream is calculated by the framework, based on the static
 * metadata field android.heic.maxAppSegmentsCount, and is assigned to both
 * Stream width and Stream bufferSize. Camera framework sets
 * Stream height to 1.
 *
 * Similar to JPEG image, the JPEG APP segment images can be of variable size,
 * so the HAL needs to include the final size of all APP segments using this
 * structure inside the output stream buffer. The camera blob ID field must be
 * set to CameraBlobId::JPEG_APP_SEGMENTS.
 *
 * The transport header must be at the end of the JPEG APP segments output stream
 * buffer. That means the blobId must start at byte[buffer_size -
 * sizeof(CameraBlob)], where the buffer_size is the size of gralloc
 * buffer. The JPEG APP segments data itself starts at the beginning of the
 * buffer and must be blobSize bytes long.
 */
@VintfStability
@Backing(type="int")
enum CameraBlobId {
    JPEG = 0x00FF,

    JPEG_APP_SEGMENTS = 0x100,
}
