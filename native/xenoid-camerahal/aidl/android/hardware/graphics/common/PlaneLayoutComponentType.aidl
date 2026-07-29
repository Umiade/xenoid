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
 * Used by IAllocator/IMapper (gralloc) to describe standard plane layout component types
 *
 * The enum values have been taken directly from gralloc1's android_flex_component for compatiblity
 * reasons. However, unlike gralloc1's android_flex_component, this field is NOT a bit field.
 * A plane's components should NOT be expressed by bitwise OR-ing different
 * PlaneLayoutComponentTypes together.
 * @hide
 */
@VintfStability
@Backing(type="long")
enum PlaneLayoutComponentType {
    /* Luma */
    Y = 1 << 0,
    /* Chroma blue */
    CB = 1 << 1,
    /* Chroma red */
    CR = 1 << 2,

    /* Red */
    R = 1 << 10,
    /* Green */
    G = 1 << 11,
    /* Blue */
    B = 1 << 12,

    /* Raw */
    RAW = 1 << 20,

    /* Alpha */
    A = 1 << 30,
}
