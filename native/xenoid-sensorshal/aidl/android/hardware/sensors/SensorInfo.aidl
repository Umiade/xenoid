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

package android.hardware.sensors;

import android.hardware.sensors.SensorType;

@VintfStability
parcelable SensorInfo {
    /**
     * Handle that identifies this sensors. This handle is used to reference
     * this sensor throughout the HAL API.
     */
    int sensorHandle;

    /**
     * Name of this sensor.
     * All sensors of the same "type" must have a different "name".
     */
    String name;

    /**
     * Vendor of the hardware part.
     */
    String vendor;

    /**
     * Version of the hardware part + driver, used for informational purposes.
     * The value of this field must increase when the driver is updated in a
     * way that changes the output of this sensor. This is important for fused
     * sensors when the fusion algorithm is updated.
     */
    int version;

    /**
     * This sensor's type.
     */
    SensorType type;

    /**
     * Type of this sensor as a string.
     *
     * When defining an OEM specific sensor or sensor manufacturer specific
     * sensor, use your reserve domain name as a prefix.
     * e.g. com.google.glass.onheaddetector
     *
     * For sensors of known type defined in SensorType (value <
     * SensorType::DEVICE_PRIVATE_BASE), this can be an empty string.
     */
    String typeAsString;

    /**
     * Maximum range of this sensor's value in SI units
     */
    float maxRange;

    /**
     * Smallest difference between two values reported by this sensor
     */
    float resolution;

    /**
     * Rough estimate of this sensor's power consumption in mA
     */
    float power;

    /**
     * This value depends on the reporting mode:
     *
     *   continuous: minimum sample period allowed in microseconds
     *   on-change : 0
     *   one-shot  :-1
     *   special   : 0, unless otherwise noted
     */
    int minDelayUs;

    /**
     * Number of events reserved for this sensor in the batch mode FIFO.
     * If there is a dedicated FIFO for this sensor, then this is the
     * size of this FIFO. If the FIFO is shared with other sensors,
     * this is the size reserved for that sensor and it can be zero.
     */
    int fifoReservedEventCount;

    /**
     * Maximum number of events of this sensor that could be batched.
     * This is especially relevant when the FIFO is shared between
     * several sensors; this value is then set to the size of that FIFO.
     */
    int fifoMaxEventCount;

    /**
     * Permission required to see this sensor, register to it and receive data.
     * Set to "" if no permission is required. Some sensor types like the
     * heart rate monitor have a mandatory require_permission.
     * For sensors that always require a specific permission, like the heart
     * rate monitor, the android framework might overwrite this string
     * automatically.
     */
    String requiredPermission;

    /**
     * This value is defined only for continuous mode and on-change sensors.
     * It is the delay between two sensor events corresponding to the lowest
     * frequency that this sensor supports. When lower frequencies are requested
     * through batch()/setDelay() the events will be generated at this frequency
     * instead.
     * It can be used by the framework or applications to estimate when the
     * batch FIFO may be full.
     *
     * continuous, on-change: maximum sampling period allowed in microseconds.
     * one-shot, special : 0
     */
    int maxDelayUs;

    /**
     * Bitmasks defined in SENSOR_FLAG_BITS_* below.
     */
    int flags;

    /**
     * Whether this sensor wakes up the AP from suspend mode when data is
     * available.  Whenever sensor events are delivered from a wake_up sensor,
     * the driver needs to hold a wake_lock till the events are read by the
     * SensorService i.e. till ISensors::poll() is called the next time.
     * Once poll is called again it means events have been read by the
     * SensorService, the driver can safely release the wake_lock. SensorService
     * will continue to hold a wake_lock till the app actually reads the events.
     */
    const int SENSOR_FLAG_BITS_WAKE_UP = 1;

    /**
     * Reporting modes for various sensors. Each sensor will have exactly one of
     * these modes set.
     * The least significant 2nd, 3rd and 4th bits are used to represent four
     * possible reporting modes.
     */
    const int SENSOR_FLAG_BITS_CONTINUOUS_MODE = 0;
    const int SENSOR_FLAG_BITS_ON_CHANGE_MODE = 2;
    const int SENSOR_FLAG_BITS_ONE_SHOT_MODE = 4;
    const int SENSOR_FLAG_BITS_SPECIAL_REPORTING_MODE = 6;

    /**
     * Set this flag if the sensor supports data_injection mode and allows data
     * to be injected from the SensorService. When in data_injection ONLY
     * sensors with this flag set are injected sensor data and only sensors with
     * this flag set are activated. Eg: Accelerometer and Step Counter sensors
     * can be set with this flag and SensorService will inject accelerometer
     * data and read the corresponding step counts.
     */
    const int SENSOR_FLAG_BITS_DATA_INJECTION = 0x10;

    /**
     * Set this flag if the sensor is a dynamically connected sensor. See
     * DynamicSensorInfo and DYNAMIC_SENSOR_META for details.
     */
    const int SENSOR_FLAG_BITS_DYNAMIC_SENSOR = 0x20;

    /**
     * Set this flag if sensor additional information is supported.
     * See ADDITIONAL_INFO and AdditionalInfo for details.
     */
    const int SENSOR_FLAG_BITS_ADDITIONAL_INFO = 0x40;

    /**
     * Set this flag if sensor suppor direct channel backed by ashmem.
     * See SharedMemType and registerDirectChannel for more details.
     */
    const int SENSOR_FLAG_BITS_DIRECT_CHANNEL_ASHMEM = 0x400;

    /**
     * Set this flag if sensor suppor direct channel backed by gralloc HAL memory.
     * See SharedMemType and registerDirectChannel for more details.
     */
    const int SENSOR_FLAG_BITS_DIRECT_CHANNEL_GRALLOC = 0x800;

    /**
     * Flags mask for reporting mode of sensor.
     */
    const int SENSOR_FLAG_BITS_MASK_REPORTING_MODE = 0xE;

    /**
     * Flags mask for direct report maximum rate level support.
     * See RateLevel.
     */
    const int SENSOR_FLAG_BITS_MASK_DIRECT_REPORT = 0x380;

    /**
     * Flags mask for all direct channel support bits.
     * See SharedMemType.
     */
    const int SENSOR_FLAG_BITS_MASK_DIRECT_CHANNEL = 0xC00;

    /**
     * Defines the number of bits different pieces of information are shifted in the
     * SENSOR_FLAG_BITS_* bitmask.
     */
    const int SENSOR_FLAG_SHIFT_REPORTING_MODE = 1;
    const int SENSOR_FLAG_SHIFT_DATA_INJECTION = 4;
    const int SENSOR_FLAG_SHIFT_DYNAMIC_SENSOR = 5;
    const int SENSOR_FLAG_SHIFT_ADDITIONAL_INFO = 6;
    const int SENSOR_FLAG_SHIFT_DIRECT_REPORT = 7;
    const int SENSOR_FLAG_SHIFT_DIRECT_CHANNEL = 10;
}
