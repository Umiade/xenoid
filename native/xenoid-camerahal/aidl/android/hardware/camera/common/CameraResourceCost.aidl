/*
 * Copyright (C) 2021 The Android Open Source Project
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

package android.hardware.camera.common;

/**
 * CameraResourceCost:
 *
 * Structure defining the abstract resource cost of opening a camera device,
 * and any usage conflicts between multiple camera devices.
 *
 * Obtainable via ICameraDevice::getResourceCost()
 */
@VintfStability
parcelable CameraResourceCost {
    /**
     * The total resource "cost" of using this camera, represented as an integer
     * value in the range [0, 100] where 100 represents total usage of the
     * shared resource that is the limiting bottleneck of the camera subsystem.
     * This may be a very rough estimate, and is used as a hint to the camera
     * service to determine when to disallow multiple applications from
     * simultaneously opening different cameras advertised by the camera
     * service.
     *
     * The camera service must be able to simultaneously open and use any
     * combination of camera devices exposed by the HAL where the sum of
     * the resource costs of these cameras is <= 100. For determining cost,
     * each camera device must be assumed to be configured and operating at
     * the maximally resource-consuming framerate and stream size settings
     * available in the configuration settings exposed for that device through
     * the camera metadata.
     *
     * The camera service may still attempt to simultaneously open combinations
     * of camera devices with a total resource cost > 100. This may succeed or
     * fail. If this succeeds, combinations of configurations that are not
     * supported due to resource constraints from having multiple open devices
     * must fail during the configure calls. If the total resource cost is <=
     * 100, open and configure must never fail for any stream configuration
     * settings or other device capabilities that would normally succeed for a
     * device when it is the only open camera device.
     *
     * This field may be used to determine whether background applications are
     * allowed to use this camera device while other applications are using
     * other camera devices. Note: multiple applications must never be allowed
     * by the camera service to simultaneously open the same camera device.
     *
     * Example use cases:
     *
     * Ex. 1: Camera Device 0 = Back Camera
     *        Camera Device 1 = Front Camera
     *   - Using both camera devices causes a large framerate slowdown due to
     *     limited ISP bandwidth.
     *
     *   Configuration:
     *
     *   Camera Device 0 - resourceCost = 51
     *                     conflicting_devices = empty
     *   Camera Device 1 - resourceCost = 51
     *                     conflicting_devices = empty
     *
     *   Result:
     *
     *   Since the sum of the resource costs is > 100, if a higher-priority
     *   application has either device open, no lower-priority applications must
     *   be allowed by the camera service to open either device. If a
     *   lower-priority application is using a device that a higher-priority
     *   subsequently attempts to open, the lower-priority application must be
     *   forced to disconnect the device.
     *
     *   If the highest-priority application chooses, it may still attempt to
     *   open both devices (since these devices are not listed as conflicting in
     *   the conflicting_devices fields), but usage of these devices may fail in
     *   the open or configure calls.
     *
     * Ex. 2: Camera Device 0 = Left Back Camera
     *        Camera Device 1 = Right Back Camera
     *        Camera Device 2 = Combined stereo camera using both right and left
     *                          back camera sensors used by devices 0, and 1
     *        Camera Device 3 = Front Camera
     *   - Due to do hardware constraints, up to two cameras may be open at
     *     once. The combined stereo camera may never be used at the same time
     *     as either of the two back camera devices (device 0, 1), and typically
     *     requires too much bandwidth to use at the same time as the front
     *     camera (device 3).
     *
     *   Configuration:
     *
     *   Camera Device 0 - resourceCost = 50
     *                     conflicting_devices = { 2 }
     *   Camera Device 1 - resourceCost = 50
     *                     conflicting_devices = { 2 }
     *   Camera Device 2 - resourceCost = 100
     *                     conflicting_devices = { 0, 1 }
     *   Camera Device 3 - resourceCost = 50
     *                     conflicting_devices = empty
     *
     *   Result:
     *
     *   Based on the conflicting_devices fields, the camera service guarantees
     *   that the following sets of open devices must never be allowed: { 1, 2
     *   }, { 0, 2 }.
     *
     *   Based on the resourceCost fields, if a high-priority foreground
     *   application is using camera device 0, a background application would be
     *   allowed to open camera device 1 or 3 (but would be forced to disconnect
     *   it again if the foreground application opened another device).
     *
     *   The highest priority application may still attempt to simultaneously
     *   open devices 0, 2, and 3, but the HAL may fail in open or configure
     *   calls for this combination.
     *
     * Ex. 3: Camera Device 0 = Back Camera
     *        Camera Device 1 = Front Camera
     *        Camera Device 2 = Low-power Front Camera that uses the same sensor
     *                          as device 1, but only exposes image stream
     *                          resolutions that can be used in low-power mode
     *  - Using both front cameras (device 1, 2) at the same time is impossible
     *    due a shared physical sensor. Using the back and "high-power" front
     *    camera (device 1) may be impossible for some stream configurations due
     *    to hardware limitations, but the "low-power" front camera option may
     *    always be used as it has special dedicated hardware.
     *
     *   Configuration:
     *
     *   Camera Device 0 - resourceCost = 100
     *                     conflicting_devices = empty
     *   Camera Device 1 - resourceCost = 100
     *                     conflicting_devices = { 2 }
     *   Camera Device 2 - resourceCost = 0
     *                     conflicting_devices = { 1 }
     *   Result:
     *
     *   Based on the conflicting_devices fields, the camera service guarantees
     *   that the following sets of open devices must never be allowed:
     *   { 1, 2 }.
     *
     *   Based on the resourceCost fields, only the highest priority application
     *   may attempt to open both device 0 and 1 at the same time. If a
     *   higher-priority application is not using device 1 or 2, a low-priority
     *   background application may open device 2 (but must be forced to
     *   disconnect it if a higher-priority application subsequently opens
     *   device 1 or 2).
     */
    int resourceCost;
    /**
     * An array of camera device IDs indicating other devices that cannot be
     * simultaneously opened while this camera device is in use.
     *
     * This field is intended to be used to indicate that this camera device
     * is a composite of several other camera devices, or otherwise has
     * hardware dependencies that prohibit simultaneous usage. If there are no
     * dependencies, an empty list may be returned to indicate this.
     *
     * The camera service must never simultaneously open any of the devices
     * in this list while this camera device is open.
     *
     */
    String[] conflictingDevices;
}
