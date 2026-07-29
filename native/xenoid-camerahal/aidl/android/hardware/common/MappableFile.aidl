/*
 * Copyright 2021 The Android Open Source Project
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

package android.hardware.common;

import android.os.ParcelFileDescriptor;

/**
 * A region of a file that can be mapped into memory.
 *
 * In Linux, MappableFile may be used with mmap as `MAP_SHARED`.
 *
 * MappableFile is compatible with ::android::base::MappedFile.
 */
@VintfStability
parcelable MappableFile {
    /**
     * Length of the mapping region in bytes.
     */
    long length;
    /**
     * The desired memory protection for the mapping.
     *
     * In Linux, prot is either `PROT_NONE` (indicating that mapped pages may not be accessed) or
     * the bitwise OR of one or more of the following flags:
     * - `PROT_READ` (indicating that the mapped pages may be read)
     * - `PROT_WRITE` (indicating that the mapped pages may be written)
     */
    int prot;
    /**
     * A handle to a mappable file.
     */
    ParcelFileDescriptor fd;
    /**
     * The offset in the file to the beginning of the mapping region in number of bytes.
     *
     * Note: Some mapping functions require that the offset is aligned to the page size.
     */
    long offset;
}
