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
 * Color transforms that may be applied by hardware composer to the whole
 * display.
 * @hide
 */
@VintfStability
@Backing(type="int")
enum ColorTransform {
    /** Applies no transform to the output color */
    IDENTITY = 0,

    /** Applies an arbitrary transform defined by a 4x4 affine matrix */
    ARBITRARY_MATRIX = 1,

    /**
     * Applies a transform that inverts the value or luminance of the color, but
     * does not modify hue or saturation
     */
    VALUE_INVERSE = 2,

    /** Applies a transform that maps all colors to shades of gray */
    GRAYSCALE = 3,

    /** Applies a transform which corrects for protanopic color blindness */
    CORRECT_PROTANOPIA = 4,

    /** Applies a transform which corrects for deuteranopic color blindness */
    CORRECT_DEUTERANOPIA = 5,

    /** Applies a transform which corrects for tritanopic color blindness */
    CORRECT_TRITANOPIA = 6
}
