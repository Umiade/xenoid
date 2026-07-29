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

@FixedSize
@VintfStability
parcelable AdditionalInfo {
    /**
     * type of payload data, see AdditionalInfoType
     */
    AdditionalInfoType type;

    /**
     * sequence number of this frame for this type
     */
    int serial;

    AdditionalInfoPayload payload;

    @FixedSize
    @VintfStability
    union AdditionalInfoPayload {
        Int32Values dataInt32;
        FloatValues dataFloat;

        @FixedSize
        @VintfStability
        parcelable Int32Values {
            int[14] values;
        }

        @FixedSize
        @VintfStability
        parcelable FloatValues {
            float[14] values;
        }
    }

    @VintfStability
    @Backing(type="int")
    enum AdditionalInfoType {
        /**
         * Marks the beginning of additional information frames
         */
        AINFO_BEGIN = 0,

        /**
         * Marks the end of additional information frames
         */
        AINFO_END = 1,

        /**
         * Estimation of the delay that is not tracked by sensor timestamps. This
         * includes delay introduced by sensor front-end filtering, data transport,
         * etc.
         * float[2]: delay in seconds, standard deviation of estimated value
         */
        AINFO_UNTRACKED_DELAY = 0x10000,

        /**
         * float: Celsius temperature
         */
        AINFO_INTERNAL_TEMPERATURE,

        /**
         * First three rows of a homogeneous matrix, which represents calibration to
         * a three-element vector raw sensor reading.
         * float[12]: 3x4 matrix in row major order
         */
        AINFO_VEC3_CALIBRATION,

        /**
         * Provides the orientation and location of the sensor element in terms of
         * the Android coordinate system. This data is given as a 3x4 matrix
         * consisting of a 3x3 rotation matrix (R) concatenated with a 3x1 location
         * vector (t). The rotation matrix provides the orientation of the Android
         * device coordinate frame relative to the local coordinate frame of the
         * sensor. Note that assuming the axes conventions of the sensor are the
         * same as Android, this is the inverse of the matrix applied to raw
         * samples read from the sensor to convert them into the Android
         * representation. The location vector represents the translation from the
         * origin of the Android sensor coordinate system to the geometric center
         * of the sensor, specified in millimeters (mm).
         *
         * float[12]: 3x4 matrix in row major order [R; t]
         *
         * Example:
         *     This raw buffer: {0, 1, 0, 0, -1, 0, 0, 10, 0, 0, 1, -2.5}
         *     Corresponds to this 3x4 matrix:
         *         0 1 0    0
         *        -1 0 0   10
         *         0 0 1 -2.5
         *     The sensor is oriented such that:
         *         - the device X axis corresponds to the sensor's local -Y axis
         *         - the device Y axis corresponds to the sensor's local X axis
         *         - the device Z axis and sensor's local Z axis are equivalent
         *     In other words, if viewing the origin of the Android coordinate
         *     system from the positive Z direction, the device coordinate frame is
         *     to be rotated 90 degrees counter-clockwise about the Z axis to align
         *     with the sensor's local coordinate frame. Equivalently, a vector in
         *     the Android coordinate frame may be multiplied with R to rotate it
         *     90 degrees clockwise (270 degrees counter-clockwise), yielding its
         *     representation in the sensor's coordinate frame.
         *     Relative to the origin of the Android coordinate system, the physical
         *     center of the sensor is located 10mm in the positive Y direction, and
         *     2.5mm in the negative Z direction.
         */
        AINFO_SENSOR_PLACEMENT,

        /**
         * float[2]: raw sample period in seconds,
         *           standard deviation of sampling period
         */
        AINFO_SAMPLING,

        /**
         * int32_t: noise type
         * float[n]: parameters
         */
        AINFO_CHANNEL_NOISE = 0x20000,

        /**
         * float[3]: sample period, standard deviation of sample period,
         * quantization unit
         */
        AINFO_CHANNEL_SAMPLER,

        /**
         * Represents a filter:
         *   \sum_j a_j y[n-j] == \sum_i b_i x[n-i]
         *
         * int32_t[3]: number of feedforward coeffients M,
         *             number of feedback coefficients N (for FIR filter, N = 1).
         *             bit mask that represents which element the filter is applied
         *             to. (bit 0==1 means this filter applies to vector element 0).
         * float[M+N]: filter coefficients (b0, b1, ..., b_{M-1}), then
         *             (a0, a1, ..., a_{N-1}), a0 is always 1.
         *
         * Multiple frames may be needed for higher number of taps.
         */
        AINFO_CHANNEL_FILTER,

        /**
         * int32_t[2]: size in (row, column) ... 1st frame
         * float[n]: matrix element values in row major order.
         */
        AINFO_CHANNEL_LINEAR_TRANSFORM,

        /**
         * int32_t[2]: extrapolate method, interpolate method
         * float[n]: mapping key points in pairs, (in, out)...
         *           (may be used to model saturation).
         */
        AINFO_CHANNEL_NONLINEAR_MAP,

        /**
         * int32_t: resample method (0-th order, 1st order...)
         * float[1]: resample ratio (upsampling if < 1.0, downsampling if > 1.0).
         */
        AINFO_CHANNEL_RESAMPLER,

        /**
         * Operation environment parameters section
         * Types in the following section is sent down (instead of reported from)
         * device as additional information to aid sensor operation. Data is sent
         * via injectSensorData() function to sensor handle -1 denoting all sensors
         * in device.
         *
         *
         * Local geomagnetic field information based on device geo location. This
         * type is primarily for for magnetic field calibration and rotation vector
         * sensor fusion.
         * float[3]: strength (uT), declination and inclination angle (rad).
         */
        AINFO_LOCAL_GEOMAGNETIC_FIELD = 0x30000,

        /**
         * Local gravitational acceleration strength at device geo location.
         * float: gravitational acceleration norm in m/s^2.
         */
        AINFO_LOCAL_GRAVITY,

        /**
         * Device dock state.
         * int32_t: dock state following Android API Intent.EXTRA_DOCK_STATE
         * definition, undefined value is ignored.
         */
        AINFO_DOCK_STATE,

        /**
         * High performance mode hint. Device is able to use up more power and take
         * more resources to improve throughput and latency in high performance mode.
         * One possible use case is virtual reality, when sensor latency need to be
         * carefully controlled.
         * int32_t: 1 or 0, denote if device is in/out of high performance mode,
         *          other values is ignored.
         */
        AINFO_HIGH_PERFORMANCE_MODE,

        /**
         * Magnetic field calibration hint. Device is notified when manually
         * triggered magnetic field calibration procedure is started or stopped. The
         * calibration procedure is assumed timed out after 1 minute from start,
         * even if an explicit stop is not received.
         *
         * int32_t: 1 for start, 0 for stop, other value is ignored.
         */
        AINFO_MAGNETIC_FIELD_CALIBRATION,

        /**
         * Custom information
         */
        AINFO_CUSTOM_START = 0x10000000,

        /**
         * Debugging
         */
        AINFO_DEBUGGING_START = 0x40000000,
    }
}
