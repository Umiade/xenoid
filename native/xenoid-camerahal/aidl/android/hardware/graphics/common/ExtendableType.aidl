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
 * This struct is used for types that are commonly extended by vendors. For example, buffer
 * compression is typically SoC specific. It is not possible for Android to define every possible
 * proprietary vendor compression strategy. Instead, compression is represented using this
 * ExtendableType that can support standard compression strategies while still allowing
 * every vendor to easily add their own non-standard definitions.
 * @hide
 */
@VintfStability
parcelable ExtendableType {
    /**
     * Name of the stable aidl interface whose value is stored in this structure.
     *
     * For standard types, the "name" field will be set to the stable aidl name of the type such as
     * "android.hardware.graphics.common.Compression".
     *
     * For custom vendor types, the "name" field will be set to the name of the custom
     * @VendorStability vendor AIDL interface such as
     * "vendor.mycompanyname.graphics.common.Compression". The name of the vendor extension should
     * contain the name of the owner of the extension. Including the company
     * name in the "name" field prevents type collisions between different vendors.
     */
    @utf8InCpp String name;

    /**
     * Enum value of the from the stable aidl interface
     *
     * For standard types, the "value" field will be set to an enum value from that stable aidl
     * type such as "NONE".
     *
     * For vendor types, the "value" field should be set to the enum value from the custom
     * @VendorStability vendor AIDL interface extended type such as "MY_COMPRESSION_TYPE1".
     */
    long value = 0;
}
