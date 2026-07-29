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

import android.hardware.common.NativeHandle;
import android.hardware.common.fmq.MQDescriptor;
import android.hardware.common.fmq.SynchronizedReadWrite;
import android.hardware.sensors.Event;
import android.hardware.sensors.ISensorsCallback;
import android.hardware.sensors.SensorInfo;

@VintfStability
interface ISensors {
    /**
     * Activate/de-activate one sensor.
     *
     * After sensor de-activation, existing sensor events that have not
     * been written to the event queue must be abandoned immediately so that
     * subsequent activations do not get stale sensor events (events
     * that are generated prior to the latter activation).
     *
     * @param sensorHandle is the handle of the sensor to change.
     * @param enabled set to true to enable, or false to disable the sensor.
     * @return Status::ok on success
     *         EX_ILLEGAL_ARGUMENT if the sensorHandle is invalid.
     */
    void activate(in int sensorHandle, in boolean enabled);

    /**
     * Sets a sensor’s parameters, including sampling frequency and maximum
     * report latency. This function can be called while the sensor is
     * activated, in which case it must not cause any sensor measurements to
     * be lost: transitioning from one sampling rate to the other cannot cause
     * lost events, nor can transitioning from a high maximum report latency to
     * a low maximum report latency.
     *
     * @param sensorHandle handle of sensor to be changed.
     * @param samplingPeriodNs specifies sensor sample period in nanoseconds.
     * @param maxReportLatencyNs allowed delay time before an event is sampled
     *     to time of report.
     * @return Status::ok on success
     *         EX_ILLEGAL_ARGUMENT if any parameters are invalid.
     */
    void batch(in int sensorHandle, in long samplingPeriodNs, in long maxReportLatencyNs);

    /**
     * Configure direct sensor event report in direct channel.
     *
     * This function start, modify rate or stop direct report of a sensor in a
     * certain direct channel.
     *
     * @param sensorHandle handle of sensor to be configured. When combined
     *     with STOP rate, sensorHandle can be -1 to denote all active sensors
     *     in the direct channel specified by channel Handle.
     * @param channelHandle handle of direct channel to be configured.
     * @param rate rate level, see RateLevel enum.
     * @param out reportToken The report token, ignored if rate is STOP.
     *     See SharedMemFormat.
     * @return The direct report token to identify multiple sensors of the same type in a single
     *         direct channel.
     * @return Status::ok on success
     *         EX_ILLEGAL_ARGUMENT if the parameter is invalid (e.g. unsupported rate level
     *          for sensor, channelHandle does not exist, etc).
     *         EX_UNSUPPORTED_OPERATION if this functionality is unsupported.
     */
    int configDirectReport(in int sensorHandle, in int channelHandle, in RateLevel rate);

    /**
     * Trigger a flush of internal FIFO.
     *
     * Flush adds a FLUSH_COMPLETE metadata event to the end of the "batch mode"
     * FIFO for the specified sensor and flushes the FIFO.  If the FIFO is empty
     * or if the sensor doesn't support batching (FIFO size zero), return
     * SUCCESS and add a trivial FLUSH_COMPLETE event added to the event stream.
     * This applies to all sensors other than one-shot sensors. If the sensor
     * is a one-shot sensor, flush must return EX_ILLEGAL_ARGUMENT and not generate any
     * flush complete metadata.  If the sensor is not active at the time flush()
     * is called, flush() return EX_ILLEGAL_ARGUMENT.
     *
     * @param sensorHandle handle of sensor to be flushed.
     * @return Status::ok on success
     *         EX_ILLEGAL_ARGUMENT if the sensorHandle is invalid.
     */
    void flush(in int sensorHandle);

    /**
     * Enumerate all available (static) sensors.
     *
     * The SensorInfo for each sensor returned by getSensorsList must be stable
     * from the initial call to getSensorsList after a device boot until the
     * entire system restarts. The SensorInfo for each sensor must not change
     * between subsequent calls to getSensorsList, even across restarts of the
     * HAL and its dependencies (for example, the sensor handle for a given
     * sensor must not change across HAL restarts).
     */
    SensorInfo[] getSensorsList();

    /**
     * Initialize the Sensors HAL's Fast Message Queues (FMQ) and callback.
     *
     * The Fast Message Queues (FMQ) that are used to send data between the
     * framework and the HAL. The callback is used by the HAL to notify the
     * framework of asynchronous events, such as a dynamic sensor connection.
     *
     * The Event FMQ is used to transport sensor events from the HAL to the
     * framework. The Event FMQ is created using the eventQueueDescriptor.
     * Data may only be written to the Event FMQ. Data must not be read from
     * the Event FMQ since the framework is the only reader. Upon receiving
     * sensor events, the HAL writes the sensor events to the Event FMQ.
     *
     * Once the HAL is finished writing sensor events to the Event FMQ, the HAL
     * must notify the framework that sensor events are available to be read and
     * processed. This is accomplished by either:
     *     1) Calling the Event FMQ’s EventFlag::wake() function with
     * EventQueueFlagBits::READ_AND_PROCESS
     *     2) Setting the write notification in the Event FMQ’s writeBlocking()
     *        function to EventQueueFlagBits::READ_AND_PROCESS.
     *
     * If the Event FMQ’s writeBlocking() function is used, the read
     * notification must be set to EventQueueFlagBits::EVENTS_READ in order to
     * be notified and unblocked when the framework has successfully read events
     * from the Event FMQ.
     *
     * The Wake Lock FMQ is used by the framework to notify the HAL when it is
     * safe to release its wake_lock. When the framework receives WAKE_UP events
     * from the Event FMQ and the framework has acquired a wake_lock, the
     * framework must write the number of WAKE_UP events processed to the Wake
     * Lock FMQ. When the HAL reads the data from the Wake Lock FMQ, the HAL
     * decrements its current count of unprocessed WAKE_UP events and releases
     * its wake_lock if the current count of unprocessed WAKE_UP events is
     * zero. It is important to note that the HAL must acquire the wake lock and
     * update its internal state regarding the number of outstanding WAKE_UP
     * events _before_ posting the event to the Wake Lock FMQ, in order to avoid
     * a race condition that can lead to loss of wake lock synchronization with
     * the framework.
     *
     * The framework must use the WAKE_LOCK_QUEUE_FLAG_BITS_DATA_WRITTEN value to
     * notify the HAL that data has been written to the Wake Lock FMQ and must
     * be read by HAL.
     *
     * The ISensorsCallback is used by the HAL to notify the framework of
     * asynchronous events, such as a dynamic sensor connection.
     *
     * The name of any wake_lock acquired by the Sensors HAL for WAKE_UP events
     * must begin with "SensorsHAL_WAKEUP".
     *
     * If WAKE_LOCK_TIMEOUT_SECONDS has elapsed since the most recent WAKE_UP
     * event was written to the Event FMQ without receiving a message on the
     * Wake Lock FMQ, then any held wake_lock for WAKE_UP events must be
     * released.
     *
     * If either the Event FMQ or the Wake Lock FMQ is already initialized when
     * initialize is invoked, then both existing FMQs must be discarded and the
     * new descriptors must be used to create new FMQs within the HAL. The
     * number of outstanding WAKE_UP events should also be reset to zero, and
     * any outstanding wake_locks held as a result of WAKE_UP events should be
     * released.
     *
     * All active sensor requests and direct channels must be closed and
     * properly cleaned up when initialize is called in order to ensure that the
     * HAL and framework's state is consistent (e.g. after a runtime restart).
     *
     * initialize must be thread safe and prevent concurrent calls
     * to initialize from simultaneously modifying state.
     *
     * @param eventQueueDescriptor Fast Message Queue descriptor that is used to
     *     create the Event FMQ which is where sensor events are written. The
     *     descriptor is obtained from the framework's FMQ that is used to read
     *     sensor events.
     * @param wakeLockDescriptor Fast Message Queue descriptor that is used to
     *     create the Wake Lock FMQ which is where wake_lock events are read
     *     from. The descriptor is obtained from the framework's FMQ that is
     *     used to write wake_lock events.
     * @param sensorsCallback sensors callback that receives asynchronous data
     *     from the Sensors HAL.
     * @return Status::ok on success
     *         EX_ILLEGAL_ARGUMENT if the descriptor is invalid (such as null).
     */
    void initialize(in MQDescriptor<Event, SynchronizedReadWrite> eventQueueDescriptor,
            in MQDescriptor<int, SynchronizedReadWrite> wakeLockDescriptor,
            in ISensorsCallback sensorsCallback);

    /**
     * Inject a single sensor event or push operation environment parameters to
     * device.
     *
     * When device is in NORMAL mode, this function is called to push operation
     * environment data to device. In this operation, Event is always of
     * SensorType::AdditionalInfo type. See operation environment parameters
     * section in AdditionalInfoType.
     *
     * When device is in DATA_INJECTION mode, this function is also used for
     * injecting sensor events.
     *
     * Regardless of OperationMode, injected SensorType::ADDITIONAL_INFO
     * type events should not be routed back to the sensor event queue.
     *
     * @see AdditionalInfoType
     * @see OperationMode
     * @param event sensor event to be injected
     * @return Status::ok on success
     *         EX_UNSUPPORTED_OPERATION if this functionality is unsupported.
     *         EX_SECURITY if the operation is not allowed.
     *         EX_SERVICE_SPECIFIC on error
     *         - ERROR_BAD_VALUE if the sensor event cannot be injected.
     */
    void injectSensorData(in Event event);

    /**
     * Register direct report channel.
     *
     * Register a direct channel with supplied shared memory information. Upon
     * return, the sensor hardware is responsible for resetting the memory
     * content to initial value (depending on memory format settings).
     *
     * @param mem shared memory info data structure.
     * @param out channelHandle The registered channel handle.
     * @return The direct channel handle, which is positive if successfully registered.
     * @return Status::ok on success
     *         EX_ILLEGAL_ARGUMENT if the shared memory information is not consistent.
     *         EX_UNSUPPORTED_OPERATION if this functionality is unsupported.
     *         EX_SERVICE_SPECIFIC on error
     *         - ERROR_NO_MEMORY if shared memory cannot be used by sensor system.
     */
    int registerDirectChannel(in SharedMemInfo mem);

    /**
     * Place the module in a specific mode.
     *
     * @see OperationMode
     * @param mode The operation mode.
     * @return Status::ok on success
     *         EX_UNSUPPORTED_OPERATION or EX_ILLEGAL_ARGUMENT if requested mode is not supported.
     *         EX_SECURITY if the operation is not allowed.
     */
    void setOperationMode(in OperationMode mode);

    /**
     * Unregister direct report channel.
     *
     * Unregister a direct channel previously registered using
     * registerDirectChannel, and remove all active sensor report configured in
     * still active sensor report configured in the direct channel.
     *
     * @param channelHandle handle of direct channel to be unregistered.
     * @return Status::ok on success
     *         EX_UNSUPPORTED_OPERATION if direct report is not supported.
     */
    void unregisterDirectChannel(in int channelHandle);

    /**
     * Direct report rate level definition. Except for SENSOR_DIRECT_RATE_STOP, each
     * rate level covers the range (55%, 220%] * nominal report rate. For example,
     * if config direct report specify a rate level SENSOR_DIRECT_RATE_FAST, it is
     * legal for sensor hardware to report event at a rate greater than 110Hz, and
     * less or equal to 440Hz. Note that rate has to remain steady without variation
     * before new rate level is configured, i.e. if a sensor is configured to
     * SENSOR_DIRECT_RATE_FAST and starts to report event at 256Hz, it cannot
     * change rate to 128Hz after a few seconds of running even if 128Hz is also in
     * the legal range of SENSOR_DIRECT_RATE_FAST. Thus, it is recommended to
     * associate report rate with RateLvel statically for single sensor.
     */
    @VintfStability
    @Backing(type="int")
    enum RateLevel {
        STOP,
        NORMAL,
        FAST,
        VERY_FAST,
    }

    @VintfStability
    @Backing(type="int")
    enum OperationMode {
        // Normal operation. Default state of the module.
        NORMAL = 0,
        // Loopback mode. Data is injected for the supported sensors by the sensor service in this
        // mode.
        DATA_INJECTION = 1,
    }

    @VintfStability
    parcelable SharedMemInfo {
        SharedMemType type;
        SharedMemFormat format;
        int size;
        NativeHandle memoryHandle;

        @VintfStability
        @Backing(type="int")
        enum SharedMemFormat {
            SENSORS_EVENT = 1,
        }

        @VintfStability
        @Backing(type="int")
        enum SharedMemType {
            ASHMEM = 1,
            GRALLOC,
        }
    }

    /**
     * Error codes that are used as service specific errors with the AIDL return
     * value EX_SERVICE_SPECIFIC.
     */
    const int ERROR_NO_MEMORY = -12;
    const int ERROR_BAD_VALUE = -22;

    /**
     * The maximum number of seconds to wait for a message on the Wake Lock FMQ
     * before automatically releasing any wake_lock held for a WAKE_UP event.
     */
    const int WAKE_LOCK_TIMEOUT_SECONDS = 1;

    /**
     * Used to notify the Event FMQ that events should be read and processed.
     */
    const int EVENT_QUEUE_FLAG_BITS_READ_AND_PROCESS = 1 << 0;

    /**
     * Used by the framework to signal to the HAL when events have been
     * successfully read from the Event FMQ.
     *
     * If the MessageQueue::writeBlocking function is being used to write sensor
     * events to the Event FMQ, then the readNotification parameter must be set
     * to EVENTS_READ.
     */
    const int EVENT_QUEUE_FLAG_BITS_EVENTS_READ = 1 << 1;

    /**
     * Used to notify the HAL that the framework has written data to the Wake
     * Lock FMQ.
     */
    const int WAKE_LOCK_QUEUE_FLAG_BITS_DATA_WRITTEN = 1 << 0;

    /**
     * Constants related to direct sensor events. The following table illustrates the
     * data format.
     *
     * Offset   Type        Name
     * -----------------------------------
     * 0x0000   int32_t     Size (always DIRECT_REPORT_SENSOR_EVENT_TOTAL_LENGTH)
     * 0x0004   int32_t     Sensor report token
     * 0x0008   int32_t     Type (see SensorType.aidl)
     * 0x000C   uint32_t    Atomic counter
     * 0x0010   int64_t     Timestamp (see Event.aidl)
     * 0x0018   float[16]/  Data
     *          int64_t[8]
     * 0x0058   int32_t[4]  Reserved (set to zero)
     */
    const int DIRECT_REPORT_SENSOR_EVENT_OFFSET_SIZE_FIELD = 0x0;
    const int DIRECT_REPORT_SENSOR_EVENT_OFFSET_SIZE_REPORT_TOKEN = 0x4;
    const int DIRECT_REPORT_SENSOR_EVENT_OFFSET_SIZE_SENSOR_TYPE = 0x8;
    const int DIRECT_REPORT_SENSOR_EVENT_OFFSET_SIZE_ATOMIC_COUNTER = 0xC;
    const int DIRECT_REPORT_SENSOR_EVENT_OFFSET_SIZE_TIMESTAMP = 0x10;
    const int DIRECT_REPORT_SENSOR_EVENT_OFFSET_SIZE_DATA = 0x18;
    const int DIRECT_REPORT_SENSOR_EVENT_OFFSET_SIZE_RESERVED = 0x58;
    const int DIRECT_REPORT_SENSOR_EVENT_TOTAL_LENGTH = 104;

    /**
     * Constants related to reserved sensor handle ranges.
     *
     * The following range (inclusive) is reserved for usage by the system for
     * runtime sensors.
     */
    const int RUNTIME_SENSORS_HANDLE_BASE = 0x5F000000;
    const int RUNTIME_SENSORS_HANDLE_END = 0x5FFFFFFF;
}
