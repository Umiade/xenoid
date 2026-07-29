/**
 * Copyright (c) 2022, The Android Open Source Project
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
 * How to interperet alpha values when it may be ambiguous.
 * @hide
 */
@VintfStability
@Backing(type="int")
enum AlphaInterpretation {
    /**
     * Alpha values are treated as coverage.
     *
     * Pixels in the buffer with an alpha of 0 (transparent) will be rendered in
     * black, and pixels with a max value will show the content underneath. An
     * alpha in between will show the content blended with black.
     */
    COVERAGE = 0,
    /**
     * Alpha values are treated as a mask.
     *
     * Pixels in the buffer with an alpha of 0 (transparent) will show the
     * content underneath, and pixels with a max value will be rendered in
     * black. An alpha in between will show the content blended with black.
     */
    MASK = 1,
}
