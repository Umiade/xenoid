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

import android.hardware.sensors.AdditionalInfo;
import android.hardware.sensors.DynamicSensorInfo;
import android.hardware.sensors.SensorStatus;
import android.hardware.sensors.SensorType;

@VintfStability
@FixedSize
parcelable Event {
    /**
     * Time measured in nanoseconds, in "elapsedRealtimeNano()'s" timebase.
     */
    long timestamp;

    /**
     * sensor identifier
     */
    int sensorHandle;

    SensorType sensorType;

    /**
     * Union discriminated on sensorType
     */
    EventPayload payload;

    /*
     * acceleration values are in meter per second per second (m/s^2)
     * magnetic vector values are in micro-Tesla (uT)
     * orientation values are in degrees
     * gyroscope values are in rad/s
     * temperature is in degrees centigrade (Celsius)
     * distance in centimeters
     * light in SI lux units
     * pressure in hectopascal (hPa)
     * relative humidity in percent
     */
    @VintfStability
    @FixedSize
    union EventPayload {
        /**
         * SensorType::ACCELEROMETER, SensorType::MAGNETIC_FIELD,
         * SensorType::ORIENTATION, SensorType::GYROSCOPE, SensorType::GRAVITY,
         * SensorType::LINEAR_ACCELERATION
         */
        Vec3 vec3;

        /**
         * SensorType::GAME_ROTATION_VECTOR
         */
        Vec4 vec4;

        /**
         * SensorType::MAGNETIC_FIELD_UNCALIBRATED,
         * SensorType::GYROSCOPE_UNCALIBRATED
         * SensorType::ACCELEROMETER_UNCALIBRATED
         */
        Uncal uncal;

        /**
         * SensorType::META_DATA
         */
        MetaData meta;

        /**
         * SensorType::DEVICE_ORIENTATION, SensorType::LIGHT, SensorType::PRESSURE,
         * SensorType::TEMPERATURE, SensorType::PROXIMITY,
         * SensorType::RELATIVE_HUMIDITY, SensorType::AMBIENT_TEMPERATURE,
         * SensorType::SIGNIFICANT_MOTION, SensorType::STEP_DETECTOR,
         * SensorType::TILT_DETECTOR, SensorType::WAKE_GESTURE,
         * SensorType::GLANCE_GESTURE, SensorType::PICK_UP_GESTURE,
         * SensorType::WRIST_TILT_GESTURE, SensorType::STATIONARY_DETECT,
         * SensorType::MOTION_DETECT, SensorType::HEART_BEAT,
         * SensorType::LOW_LATENCY_OFFBODY_DETECT, SensorType::MOISTURE_INTRUSION
         */
        float scalar;

        /**
         * SensorType::STEP_COUNTER
         */
        long stepCount;

        /**
         * SensorType::HEART_RATE
         */
        HeartRate heartRate;

        /**
         * SensorType::POSE_6DOF
         */
        Pose6Dof pose6DOF;

        /**
         * SensorType::DYNAMIC_SENSOR_META
         */
        DynamicSensorInfo dynamic;

        /**
         * SensorType::ADDITIONAL_INFO
         */
        AdditionalInfo additional;

        /**
         * The following sensors should use the data field:
         * - Undefined/custom sensor type >= SensorType::DEVICE_PRIVATE_BASE
         * - SensorType::ROTATION_VECTOR, SensorType::GEOMAGNETIC_ROTATION_VECTOR:
         *   - These are Vec4 types with an additional float accuracy field,
         *     where data[4] is the estimated heading accuracy in radians
         *     (-1 if unavailable, and invalid if not in the range (0, 2 * pi]).
         */
        Data data;

        /**
         * SensorType::HEAD_TRACKER
         */
        HeadTracker headTracker;

        /**
         * SensorType::ACCELEROMETER_LIMITED_AXES
         * SensorType::GYROSCOPE_LIMITED_AXES
         */
        LimitedAxesImu limitedAxesImu;

        /**
         * SensorType::ACCELEROMETER_LIMITED_AXES_UNCALIBRATED
         * SensorType::GYROSCOPE_LIMITED_AXES_UNCALIBRATED
         */
        LimitedAxesImuUncal limitedAxesImuUncal;

        /**
         * SensorType::HEADING
         */
        Heading heading;

        @FixedSize
        @VintfStability
        parcelable Vec4 {
            float x;
            float y;
            float z;
            float w;
        }

        @FixedSize
        @VintfStability
        parcelable Vec3 {
            float x;
            float y;
            float z;
            SensorStatus status;
        }

        @FixedSize
        @VintfStability
        parcelable Uncal {
            float x;
            float y;
            float z;
            float xBias;
            float yBias;
            float zBias;
        }

        /**
         * Payload of the HEAD_TRACKER sensor type. Note that the axis
         * definition of this sensor type differs from the rest of Android. See
         * SensorType::HEAD_TRACKER for more information.
         */
        @FixedSize
        @VintfStability
        parcelable HeadTracker {
            /**
             * An Euler vector (rotation vector, i.e. a vector whose direction
             * indicates the axis of rotation and magnitude indicates the angle
             * to rotate around that axis) representing the transform from
             * the (arbitrary, possibly slowly drifting) reference frame to the
             * head frame. Expressed in radians. Magnitude of the vector must be
             * in the range [0, pi], while the value of individual axes are
             * in the range [-pi, pi].
             */
            float rx;
            float ry;
            float rz;

            /**
             * An Euler vector (rotation vector) representing the angular
             * velocity of the head (relative to itself), in radians per second.
             * The direction of this vector indicates the axis of rotation, and
             * the magnitude indicates the rate of rotation.
             * If this head tracker sensor instance does not support detecting
             * velocity, then these fields must be set to 0.
             */
            float vx;
            float vy;
            float vz;

            /**
             * This value increments (or wraps around to 0) each time the
             * reference frame is suddenly and significantly changed, for
             * example if an orientation filter algorithm used for determining
             * the orientation has had its state reset.
             */
            int discontinuityCount;
        }

        /**
         * Payload of the ACCELEROMETER_LIMITED_AXES and GYROSCOPE_LIMITED_AXES
         * sensor types.
         */
        @FixedSize
        @VintfStability
        parcelable LimitedAxesImu {
            /**
             * Acceleration or angular speed values.  If certain axes are not
             * supported, the associated value must be set to 0.
             */
            float x;
            float y;
            float z;

            /**
             * Limited axes sensors must not be supported for all three axes.
             * These values indicate which axes are supported with a 1.0 for
             * supported, and a 0 for not supported. The supported axes should
             * be determined at build time and these values must not change
             * during runtime.
             */
            float xSupported;
            float ySupported;
            float zSupported;
        }

        /**
         * Payload of the ACCELEROMETER_LIMITED_AXES_UNCALIBRATED and
         * GYROSCOPE_LIMITED_AXES_UNCALIBRATED sensor types.
         */
        @FixedSize
        @VintfStability
        parcelable LimitedAxesImuUncal {
            /**
             * Acceleration (without bias compensation) or angular (speed
             * (without drift compensation) values. If certain axes are not
             * supported, the associated value must be set to 0.
             */
            float x;
            float y;
            float z;

            /**
             * Estimated bias values for uncalibrated accelerometer or
             * estimated drift values for uncalibrated gyroscope. If certain
             * axes are not supported, the associated value must be set to 0.
             */
            float xBias;
            float yBias;
            float zBias;

            /**
             * Limited axes sensors must not be supported for all three axes.
             * These values indicate which axes are supported with a 1.0 for
             * supported, and a 0 for not supported. The supported axes should
             * be determined at build time and these values must not change
             * during runtime.
             */
            float xSupported;
            float ySupported;
            float zSupported;
        }

        @FixedSize
        @VintfStability
        parcelable HeartRate {
            /**
             * Heart rate in beats per minute.
             * Set to 0 when status is SensorStatus::UNRELIABLE or
             * SensorStatus::NO_CONTACT
             */
            float bpm;
            /**
             * Status of the heart rate sensor for this reading.
             */
            SensorStatus status;
        }

        @FixedSize
        @VintfStability
        parcelable Heading {
            /**
             * The direction in which the device is pointing relative to true
             * north in degrees. The value must be between 0.0 (inclusive) and
             * 360.0 (exclusive), with 0 indicating north, 90 east, 180 south,
             * and 270 west.
             */
            float heading;
            /**
             * Accuracy is defined at 68% confidence. In the case where the
             * underlying distribution is assumed Gaussian normal, this would be
             * considered one standard deviation. For example, if the heading
             * returns 60 degrees, and accuracy returns 10 degrees, then there
             * is a 68 percent probability of the true heading being between 50
             * degrees and 70 degrees.
             */
            float accuracy;
        }

        @FixedSize
        @VintfStability
        parcelable MetaData {
            MetaDataEventType what;

            @VintfStability
            @Backing(type="int")
            enum MetaDataEventType {
                META_DATA_FLUSH_COMPLETE = 1,
            }
        }

        @FixedSize
        @VintfStability
        parcelable Pose6Dof {
            float[15] values;
        }

        @FixedSize
        @VintfStability
        parcelable Data {
            float[16] values;
        }
    }
}
