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

import android.hardware.graphics.common.PixelFormat;
import android.hardware.graphics.common.AlphaInterpretation;

/**
 * A description of how a device supports Composition.DISPLAY_DECORATION.
 *
 * If the device supports Composition.DISPLAY_DECORATION, a call to
 * IComposerClient.getDisplayDecorationSupport should return an instance of this
 * parcelable. Otherwise the method should return null.
 * @hide
 */
@VintfStability
parcelable DisplayDecorationSupport {
    /**
     * The format to use for DISPLAY_DECORATION layers. Other formats are not
     * supported. If other formats are used with DISPLAY_DECORATION, the result
     * is undefined.
     */
    PixelFormat format;
    /**
     * How the device intreprets the alpha in the pixel buffer.
     */
    AlphaInterpretation alphaInterpretation;
}
