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
 * Used by IAllocator/IMapper (gralloc) to describe standard interlaced strategies
 * @hide
 */
@VintfStability
@Backing(type="long")
enum Interlaced {
    /* The buffer is not interlaced. */
    NONE = 0,

    /* The buffer's planes are interlaced horizontally. The height of each interlaced plane is
     * 1/2 the height of the buffer's height. */
    TOP_BOTTOM = 1,

    /* The buffer's planes are interlaced vertically. The width of each interlaced plane is
     * 1/2 the width of the buffer's width. */
    RIGHT_LEFT = 2,
}
