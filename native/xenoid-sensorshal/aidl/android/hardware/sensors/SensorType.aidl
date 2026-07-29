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

@VintfStability
@Backing(type="int")
enum SensorType {
    /**
     * META_DATA is a special event type used to populate the MetaData
     * structure. It doesn't correspond to a physical sensor. Events of this
     * type exist only inside the HAL, their primary purpose is to signal the
     * completion of a flush request.
     */
    META_DATA = 0,

    /**
     * ACCELEROMETER
     * reporting-mode: continuous
     *
     * All values are in SI units (m/s^2) and measure the acceleration of the
     * device minus the acceleration due to gravity.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    ACCELEROMETER = 1,

    /**
     * MAGNETIC_FIELD
     * reporting-mode: continuous
     *
     * All values are in micro-Tesla (uT) and measure the geomagnetic
     * field in the X, Y and Z axis.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    MAGNETIC_FIELD = 2,

    /**
     * ORIENTATION
     * reporting-mode: continuous
     *
     * All values are angles in degrees.
     *
     * Orientation sensors return sensor events for all 3 axes at a constant
     * rate defined by setDelay().
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    ORIENTATION = 3,

    /**
     * GYROSCOPE
     * reporting-mode: continuous
     *
     * All values are in radians/second and measure the rate of rotation
     * around the X, Y and Z axis.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    GYROSCOPE = 4,

    /**
     * LIGHT
     * reporting-mode: on-change
     *
     * The light sensor value is returned in SI lux units.
     *
     * Both wake-up and non wake-up versions are useful.
     */
    LIGHT = 5,

    /**
     * PRESSURE
     * reporting-mode: continuous
     *
     * The pressure sensor return the athmospheric pressure in hectopascal (hPa)
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    PRESSURE = 6,

    /**
     * PROXIMITY
     * reporting-mode: on-change
     *
     * The proximity sensor which turns the screen off and back on during calls
     * is the wake-up proximity sensor. Implement wake-up proximity sensor
     * before implementing a non wake-up proximity sensor. For the wake-up
     * proximity sensor set the flag SENSOR_FLAG_WAKE_UP.
     * The value corresponds to the distance to the nearest object in
     * centimeters.
     */
    PROXIMITY = 8,

    /**
     * GRAVITY
     * reporting-mode: continuous
     *
     * A gravity output indicates the direction of and magnitude of gravity in
     * the devices's coordinates.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    GRAVITY = 9,

    /**
     * LINEAR_ACCELERATION
     * reporting-mode: continuous
     *
     * Indicates the linear acceleration of the device in device coordinates,
     * not including gravity.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    LINEAR_ACCELERATION = 10,

    /**
     * ROTATION_VECTOR
     * reporting-mode: continuous
     *
     * The rotation vector symbolizes the orientation of the device relative to
     * the East-North-Up coordinates frame.
     *
     * Note that despite the name, SensorType::ROTATION_VECTOR uses
     * quaternion representation, rather than the rotation vector representation
     * (aka Euler vector) seen in SensorType::HEAD_TRACKER.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    ROTATION_VECTOR = 11,

    /**
     * RELATIVE_HUMIDITY
     * reporting-mode: on-change
     *
     * A relative humidity sensor measures relative ambient air humidity and
     * returns a value in percent.
     *
     * Both wake-up and non wake-up versions are useful.
     */
    RELATIVE_HUMIDITY = 12,

    /**
     * AMBIENT_TEMPERATURE
     * reporting-mode: on-change
     *
     * The ambient (room) temperature in degree Celsius.
     *
     * Both wake-up and non wake-up versions are useful.
     */
    AMBIENT_TEMPERATURE = 13,

    /**
     * MAGNETIC_FIELD_UNCALIBRATED
     * reporting-mode: continuous
     *
     * Similar to MAGNETIC_FIELD, but the hard iron calibration is
     * reported separately instead of being included in the measurement.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    MAGNETIC_FIELD_UNCALIBRATED = 14,

    /**
     * GAME_ROTATION_VECTOR
     * reporting-mode: continuous
     *
     * Similar to ROTATION_VECTOR, but not using the geomagnetic
     * field.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    GAME_ROTATION_VECTOR = 15,

    /**
     * GYROSCOPE_UNCALIBRATED
     * reporting-mode: continuous
     *
     * All values are in radians/second and measure the rate of rotation
     * around the X, Y and Z axis.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    GYROSCOPE_UNCALIBRATED = 16,

    /**
     * SIGNIFICANT_MOTION
     * reporting-mode: one-shot
     *
     * A sensor of this type triggers an event each time significant motion
     * is detected and automatically disables itself.
     * For Significant Motion sensor to be useful, it must be defined as a
     * wake-up sensor. (set SENSOR_FLAG_WAKE_UP). Implement the wake-up
     * significant motion sensor. A non wake-up version is not useful.
     * The only allowed value to return is 1.0.
     */
    SIGNIFICANT_MOTION = 17,

    /**
     * STEP_DETECTOR
     * reporting-mode: special
     *
     * A sensor of this type triggers an event each time a step is taken
     * by the user. The only allowed value to return is 1.0 and an event
     * is generated for each step.
     *
     * Both wake-up and non wake-up versions are useful.
     */
    STEP_DETECTOR = 18,

    /**
     * STEP_COUNTER
     * reporting-mode: on-change
     *
     * A sensor of this type returns the number of steps taken by the user since
     * the last reboot while activated. The value is returned as a uint64_t and
     * is reset to zero only on a system / android reboot.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    STEP_COUNTER = 19,

    /**
     * GEOMAGNETIC_ROTATION_VECTOR
     * reporting-mode: continuous
     *
     *  Similar to ROTATION_VECTOR, but using a magnetometer instead
     *  of using a gyroscope.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    GEOMAGNETIC_ROTATION_VECTOR = 20,

    /**
     * HEART_RATE
     * reporting-mode: on-change
     *
     *  A sensor of this type returns the current heart rate.
     *  The events contain the current heart rate in beats per minute (BPM) and
     *  the status of the sensor during the measurement. See "HeartRate" below
     *  for more details.
     *
     *  Because this sensor is on-change, events must be generated when and only
     *  when heart_rate.bpm or heart_rate.status have changed since the last
     *  event. In particular, upon the first activation, unless the device is
     *  known to not be on the body, the status field of the first event must be
     *  set to SensorStatus::UNRELIABLE. The event should be generated no faster
     *  than every period_ns passed to setDelay() or to batch().
     *  See the definition of the on-change reporting mode for more information.
     *
     *  SensorInfo.requiredPermission must be set to
     *  SENSOR_PERMISSION_BODY_SENSORS.
     *
     *  Both wake-up and non wake-up versions are useful.
     */
    HEART_RATE = 21,

    /**
     * WAKE_UP_TILT_DETECTOR
     * reporting-mode: special (setDelay has no impact)
     *
     * A sensor of this type generates an event each time a tilt event is
     * detected. A tilt event must be generated if the direction of the
     * 2-seconds window average gravity changed by at least 35 degrees since the
     * activation or the last trigger of the sensor.
     *
     *  reference_estimated_gravity = average of accelerometer measurements over
     *  the first 1 second after activation or the estimated gravity at the last
     *  trigger.
     *
     *  current_estimated_gravity = average of accelerometer measurements over
     *  the last 2 seconds.
     *
     *  trigger when
     *     angle(reference_estimated_gravity, current_estimated_gravity)
     *       > 35 degrees
     *
     * Large accelerations without a change in phone orientation must not
     * trigger a tilt event.
     * For example, a sharp turn or strong acceleration while driving a car
     * must not trigger a tilt event, even though the angle of the average
     * acceleration might vary by more than 35 degrees.
     *
     * Typically, this sensor is implemented with the help of only an
     * accelerometer. Other sensors can be used as well if they do not increase
     * the power consumption significantly. This is a low power sensor that
     * must allow the AP to go into suspend mode. Do not emulate this sensor
     * in the HAL.
     * Like other wake up sensors, the driver is expected to a hold a wake_lock
     * with a timeout of 200 ms while reporting this event. The only allowed
     * return value is 1.0.
     *
     * Implement only the wake-up version of this sensor.
     */
    TILT_DETECTOR = 22,

    /**
     * WAKE_GESTURE
     * reporting-mode: one-shot
     *
     * A sensor enabling waking up the device based on a device specific motion.
     *
     * When this sensor triggers, the device behaves as if the power button was
     * pressed, turning the screen on. This behavior (turning on the screen when
     * this sensor triggers) might be deactivated by the user in the device
     * settings. Changes in settings do not impact the behavior of the sensor:
     * only whether the framework turns the screen on when it triggers.
     *
     * The actual gesture to be detected is not specified, and can be chosen by
     * the manufacturer of the device.
     * This sensor must be low power, as it is likely to be activated 24/7.
     * The only allowed value to return is 1.0.
     *
     * Implement only the wake-up version of this sensor.
     */
    WAKE_GESTURE = 23,

    /**
     * GLANCE_GESTURE
     * reporting-mode: one-shot
     *
     * A sensor enabling briefly turning the screen on to enable the user to
     * glance content on screen based on a specific motion.  The device must
     * turn the screen off after a few moments.
     *
     * When this sensor triggers, the device turns the screen on momentarily
     * to allow the user to glance notifications or other content while the
     * device remains locked in a non-interactive state (dozing). This behavior
     * (briefly turning on the screen when this sensor triggers) might be
     * deactivated by the user in the device settings.
     * Changes in settings do not impact the behavior of the sensor: only
     * whether the framework briefly turns the screen on when it triggers.
     *
     * The actual gesture to be detected is not specified, and can be chosen by
     * the manufacturer of the device.
     * This sensor must be low power, as it is likely to be activated 24/7.
     * The only allowed value to return is 1.0.
     *
     * Implement only the wake-up version of this sensor.
     */
    GLANCE_GESTURE = 24,

    /**
     * PICK_UP_GESTURE
     * reporting-mode: one-shot
     *
     * A sensor of this type triggers when the device is picked up regardless of
     * wherever is was before (desk, pocket, bag). The only allowed return value
     * is 1.0. This sensor de-activates itself immediately after it triggers.
     *
     * Implement only the wake-up version of this sensor.
     */
    PICK_UP_GESTURE = 25,

    /**
     * WRIST_TILT_GESTURE
     * trigger-mode: special
     * wake-up sensor: yes
     *
     * A sensor of this type triggers an event each time a tilt of the
     * wrist-worn device is detected.
     *
     * This sensor must be low power, as it is likely to be activated 24/7.
     * The only allowed value to return is 1.0.
     *
     * Implement only the wake-up version of this sensor.
     */
    WRIST_TILT_GESTURE = 26,

    /**
     * DEVICE_ORIENTATION
     * reporting-mode: on-change
     *
     * The current orientation of the device. The value is reported in
     * the "scalar" element of the EventPayload in Event. The
     * only values that can be reported are (please refer to Android Sensor
     * Coordinate System to understand the X and Y axis direction with respect
     * to default orientation):
     *  - 0: device is in default orientation (Y axis is vertical and points up)
     *  - 1: device is rotated 90 degrees counter-clockwise from default
     *       orientation (X axis is vertical and points up)
     *  - 2: device is rotated 180 degrees from default orientation (Y axis is
     *       vertical and points down)
     *  - 3: device is rotated 90 degrees clockwise from default orientation
     *       (X axis is vertical and points down)
     *
     * Moving the device to an orientation where the Z axis is vertical (either
     * up or down) must not cause a new event to be reported.
     *
     * To improve the user experience of this sensor, it is recommended to
     * implement some physical (i.e., rotation angle) and temporal (i.e., delay)
     * hysteresis. In other words, minor or transient rotations must not cause
     * a new event to be reported.
     *
     * This is a low power sensor that intended to reduce interrupts of
     * application processor and thus allow it to go sleep. Use hardware
     * implementation based on low power consumption sensors, such as
     * accelerometer. Device must not emulate this sensor in the HAL.
     *
     * Both wake-up and non wake-up versions are useful.
     */
    DEVICE_ORIENTATION = 27,

    /**
     * POSE_6DOF
     * trigger-mode: continuous
     *
     * A sensor of this type returns the pose of the device.
     * Pose of the device is defined as the orientation of the device from a
     * Earth Centered Earth Fixed frame and the translation from an arbitrary
     * point at subscription.
     *
     * This sensor can be high power. It can use any and all of the following
     *           . Accelerometer
     *           . Gyroscope
     *           . Camera
     *           . Depth Camera
     *
     */
    POSE_6DOF = 28,

    /**
     * STATIONARY_DETECT
     * trigger mode: one shot
     *
     * A sensor of this type returns an event if the device is still/stationary
     * for a while. The period of time to monitor for stationarity must be
     * greater than 5 seconds. The latency must be less than 10 seconds.
     *
     * Stationarity here refers to absolute stationarity. eg: device on desk.
     *
     * The only allowed value to return is 1.0.
     */
    STATIONARY_DETECT = 29,

    /**
     * MOTION_DETECT
     * trigger mode: one shot
     *
     * A sensor of this type returns an event if the device is not still for
     * for a while. The period of time to monitor for stationarity must be
     * greater than 5 seconds. The latency must be less than 10 seconds.
     *
     * Motion here refers to any mechanism in which the device is causes to be
     * moved in its inertial frame. eg: Pickin up the device and walking with it
     * to a nearby room may trigger motion wherewas keeping the device on a
     * table on a smooth train moving at constant velocity may not trigger
     * motion.
     *
     * The only allowed value to return is 1.0.
     */
    MOTION_DETECT = 30,

    /**
     * HEART_BEAT
     * trigger mode: continuous
     *
     * A sensor of this type returns an event everytime a hear beat peak is
     * detected.
     *
     * Peak here ideally corresponds to the positive peak in the QRS complex of
     * and ECG signal.
     *
     * The sensor is not expected to be optimized for latency. As a guide, a
     * latency of up to 10 seconds is acceptable. However, the timestamp attached
     * to the event must be accuratly correspond to the time the peak occurred.
     *
     * The sensor event contains a parameter for the confidence in the detection
     * of the peak where 0.0 represent no information at all, and 1.0 represents
     * certainty.
     */
    HEART_BEAT = 31,

    /**
     * DYNAMIC_SENSOR_META
     * trigger-mode: special
     * wake-up sensor: yes
     *
     * A sensor event of this type is received when a dynamic sensor is added to
     * or removed from the system. At most one sensor of this type can be
     * present in one sensor HAL implementation and presence of a sensor of this
     * type in sensor HAL implementation indicates that this sensor HAL supports
     * dynamic sensor feature. Operations, such as batch, activate and setDelay,
     * to this special purpose sensor must be treated as no-op and return
     * successful; flush() also has to generate flush complete event as if this
     * is a sensor that does not support batching.
     *
     * A dynamic sensor connection indicates connection of a physical device or
     * instantiation of a virtual sensor backed by algorithm; and a dynamic
     * sensor disconnection indicates the opposite. A sensor event of
     * DYNAMIC_SENSOR_META type should be delivered regardless of
     * the activation status of the sensor in the event of dynamic sensor
     * connection and disconnection. In the sensor event, besides the common
     * data entries, "dynamic_sensor_meta", which includes fields for connection
     * status, handle of the sensor involved, pointer to sensor_t structure and
     * a uuid field, must be populated.
     *
     * At a dynamic sensor connection event, fields of sensor_t structure
     * referenced by a pointer in dynamic_sensor_meta must be filled as if it
     * was regular sensors. Sensor HAL is responsible for recovery of memory if
     * the corresponding data is dynamicially allocated. However, the
     * pointer must be valid until the first activate call to the sensor
     * reported in this connection event. At a dynamic sensor disconnection,
     * the sensor_t pointer must be NULL.
     *
     * The sensor handle assigned to dynamic sensors must never be the same as
     * that of any regular static sensors, and must be unique until next boot.
     * In another word, if a handle h is used for a dynamic sensor A, that same
     * number cannot be used for the same dynamic sensor A or another dynamic
     * sensor B even after disconnection of A until reboot.
     *
     * The UUID field will be used for identifying the sensor in addition to
     * name, vendor and version and type. For physical sensors of the same
     * model, all sensors will have the same values in sensor_t, but the UUID
     * must be unique and persistent for each individual unit. An all zero
     * UUID indicates it is not possible to differentiate individual sensor
     * unit.
     *
     */
    DYNAMIC_SENSOR_META = 32,

    /**
     * ADDITIONAL_INFO
     * reporting-mode: N/A
     *
     * This sensor type is for delivering additional sensor information aside
     * from sensor event data.
     * Additional information may include sensor front-end group delay, internal
     * calibration parameters, noise level metrics, device internal temperature,
     * etc.
     *
     * This type will never bind to a sensor. In other words, no sensor in the
     * sensor list can have the type SENSOR_TYPE_ADDITIONAL_INFO. If a
     * sensor HAL supports sensor additional information feature, it reports
     * sensor_event_t with "sensor" field set to handle of the reporting sensor
     * and "type" field set to ADDITIONAL_INFO. Delivery of
     * additional information events is triggered under two conditions: an
     * enable activate() call or a flush() call to the corresponding sensor.
     * Besides, time varying parameters can update infrequently without being
     * triggered. Device is responsible to control update rate. The recommend
     * update rate is less than 1/1000 of sensor event rate or less than once
     * per minute in average.
     *
     * A single additional information report consists of multiple frames.
     * Sequences of these frames are ordered using timestamps, which means the
     * timestamps of sequential frames have to be at least 1 nanosecond apart
     * from each other. Each frame is a sensor_event_t delivered through the HAL
     * interface, with related data stored in the "additional_info" field, which
     * is of type additional_info_event_t.
     * The "type" field of additional_info_event_t denotes the nature of the
     * payload data (see additional_info_type_t).
     * The "serial" field is used to keep the sequence of payload data that
     * spans multiple frames. The first frame of the entire report is always of
     * type AINFO_BEGIN, and the last frame is always AINFO_END.
     *
     * If flush() was triggering the report, all additional information frames
     * must be delivered after flush complete event.
     */
    ADDITIONAL_INFO = 33,

    /**
     * LOW_LATENCY_OFFBODY_DETECT
     * trigger-mode: on-change
     * wake-up sensor: yes
     *
     * A sensor of this type is defined for devices that are supposed to be worn
     * by the user in the normal use case (such as a watch, wristband, etc) and
     * is not yet defined for other device.
     *
     * A sensor of this type triggers an event each time the wearable device
     * is removed from the body and each time it's put back onto the body.
     * It must be low-latency and be able to detect the on-body to off-body
     * transition within one second (event delivery time included),
     * and 3-second latency to determine the off-body to on-body transition
     * (event delivery time included).
     *
     * There are only two valid event values for the sensor to return :
     *    0.0 for off-body
     *    1.0 for on-body
     *
     */
    LOW_LATENCY_OFFBODY_DETECT = 34,

    /**
     * ACCELEROMETER_UNCALIBRATED
     * reporting-mode: continuous
     *
     * All values are in SI units (m/s^2) and measure the acceleration of the
     * device minus the acceleration due to gravity.
     *
     * Implement the non-wake-up version of this sensor and implement the
     * wake-up version if the system possesses a wake up fifo.
     */
    ACCELEROMETER_UNCALIBRATED = 35,

    /**
     * HINGE_ANGLE
     * reporting-mode: on-change
     * wake-up sensor: yes
     *
     * A sensor of this type measures the angle, in degrees, between two
     * integral parts of the device. Movement of a hinge measured by this sensor
     * type is expected to alter the ways in which the user may interact with
     * the device, for example by unfolding or revealing a display.
     *
     * Sensor data is output using EventPayload.scalar.
     *
     * Implement wake-up proximity sensor before implementing a non wake-up
     * proximity sensor.
     */
    HINGE_ANGLE = 36,

    /**
     * HEAD_TRACKER
     * reporting-mode: continuous
     *
     * A sensor of this type measures the orientation of a user's head relative
     * to an arbitrary reference frame, and the rate of rotation.
     *
     * Events produced by this sensor follow a special head-centric coordinate
     * frame, where:
     *   - The X axis crosses through the user's ears, with the positive X
     *     direction extending out of the user's right ear
     *   - The Y axis crosses from the back of the user's head through their
     *     nose, with the positive direction extending out of the nose, and the
     *     X/Y plane being nominally parallel to the ground when the user is
     *     upright and looking straight ahead
     *   - The Z axis crosses from the neck through the top of the user's head,
     *     with the positive direction extending out from the top of the head
     *
     * When this sensor type is exposed as a dynamic sensor through a
     * communications channel that uses HID, such as Bluetooth or USB, as part
     * of a device with audio output capability (e.g. headphones), then the
     * DynamicSensorInfo::uuid field shall be set to contents of the HID
     * Persistent Unique ID to permit association between the sensor and audio
     * device. Accordingly, the HID Persistent Unique ID (Sensors Page 0x20,
     * Usage ID 0x302) must be populated as a UUID in binary representation,
     * following RFC 4122 byte order.
     */
    HEAD_TRACKER = 37,

    /**
     * ACCELEROMETER_LIMITED_AXES
     * reporting-mode: continuous
     *
     * Equivalent to ACCELEROMETER, but supporting cases where one or two axes
     * are not supported.
     */
    ACCELEROMETER_LIMITED_AXES = 38,

    /**
     * GYROSCOPE_LIMITED_AXES
     * reporting-mode: continuous
     *
     * Equivalent to GYROSCOPE, but supporting cases where one or two axes are
     * not supported.
     */
    GYROSCOPE_LIMITED_AXES = 39,

    /**
     * ACCELEROMETER_LIMITED_AXES_UNCALIBRATED
     * reporting-mode: continuous
     *
     * Equivalent to ACCELEROMETER_UNCALIBRATED, but supporting cases where one
     * or two axes are not supported.
     */
    ACCELEROMETER_LIMITED_AXES_UNCALIBRATED = 40,

    /**
     * GYROSCOPE_LIMITED_AXES_UNCALIBRATED
     * reporting-mode: continuous
     *
     * Equivalent to GYROSCOPE_UNCALIBRATED, but supporting cases where one or
     * two axes are not supported.
     */
    GYROSCOPE_LIMITED_AXES_UNCALIBRATED = 41,

    /**
     * HEADING
     * reporting-mode: continuous
     *
     * A sensor of this type measures the direction in which the device is
     * pointing relative to true north in degrees.
     *
     * This sensor was added for automotive form factors. Other devices with a
     * clear forward direction might find it useful as well. However, devices
     * with a more ambiguous orientation such as phones or wearables might want
     * to consider using other sensors such as Sensor.TYPE_ROTATION_VECTOR
     * which might be more suitable.
     */
    HEADING = 42,

    /**
     * MOISTURE_INTRUSION
     * trigger mode: on-change
     *
     * Detects moisture intrusion in the chassis of device. This detection is
     * one-way and persistent. Once a device is detected to have water damage,
     * it will always report 1 (across factory reset /reboot) even if moisture
     * is no longer present, until the device has been repaired.
     * The only allowed values to return are:
     *   0.0: no moisture intrusion detected in relevant history
     *   1.0: moisture intrusion detected now or previously
     */
    MOISTURE_INTRUSION = 43,

    /**
     * Base of the range reserved for device manufacturers' private sensor
     * types. These sensor types aren't documented in the SDK.
     */
    DEVICE_PRIVATE_BASE = 0x10000,
}
