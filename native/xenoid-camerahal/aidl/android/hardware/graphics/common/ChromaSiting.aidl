/**
 * Copyright (c) 2019, The Android Open Source Project
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
 * Used by IAllocator/IMapper (gralloc) to describe standard chroma siting
 * @hide
 */
@VintfStability
@Backing(type="long")
enum ChromaSiting {
    /* This format does not have chroma siting. */
    NONE = 0,

    /* This format has chroma siting but the type being used is unknown. */
    UNKNOWN = 1,

    /* Cb and Cr are sited interstitially, halfway between alternate luma samples.
     * This is used by 4:2:0 for JPEG/JFIF, H.261, MPEG-1. */
    SITED_INTERSTITIAL = 2,

    /* Cb and Cr are horizontally sited coincident with a luma sample.
     * Cb and Cr are vertically sited interstitially.
     * This is used by 4:2:0 for MPEG-2 frame pictures. */
    COSITED_HORIZONTAL = 3,
}
