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
import android.hardware.graphics.common.XyColor;

/**
 * Mastering display metadata as specified by SMPTE ST 2086.
 *
 * This is an AIDL counterpart of the NDK struct `AHdrMetadata_smpte2086`.
 * @hide
 */
@VintfStability
parcelable Smpte2086 {
    /**
     * CIE XYZ chromaticity for red in the RGB primaries.
     */
    XyColor primaryRed;
    /**
     * CIE XYZ chromaticity for green in the RGB primaries.
     */
    XyColor primaryGreen;
    /**
     * CIE XYZ chromaticity for blue in the RGB primaries.
     */
    XyColor primaryBlue;
    /**
     * CIE XYZ chromaticity for the white point.
     */
    XyColor whitePoint;
    /**
     * Maximum luminance in candelas per square meter.
     */
    float maxLuminance;
    /**
     * Minimum luminance in candelas per square meter.
     */
    float minLuminance;
}
