/**
 * Copyright (c) 2021, The Android Open Source Project
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
 * Transformation definitions
 * @hide
 */
@VintfStability
@Backing(type="int")
enum Transform {
    /**
     * Identity transform (i.e. no rotation or flip).
     */
    NONE = 0,

    /**
     * Horizontal flip. FLIP_H/FLIP_V is applied before ROT_90.
     */
    FLIP_H = 1 << 0,

    /**
     * Vertical flip. FLIP_H/FLIP_V is applied before ROT_90.
     */
    FLIP_V = 1 << 1,

    /**
     * 90 degree clockwise rotation. FLIP_H/FLIP_V is applied before ROT_90.
     */
    ROT_90 = 1 << 2,

    /**
     * Commonly used combinations.
     */
    ROT_180 = FLIP_H | FLIP_V,
    ROT_270 = FLIP_H | FLIP_V | ROT_90,
}
