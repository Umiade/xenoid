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

import android.hardware.sensors.SensorInfo;

@VintfStability
interface ISensorsCallback {
    /**
     * Notify the framework that new dynamic sensors have been connected.
     *
     * If a dynamic sensor was previously connected and has not been
     * disconnected, then that sensor must not be included in sensorInfos.
     *
     * @param sensorInfos vector of SensorInfo for each dynamic sensor that
     *     was connected.
     */
    void onDynamicSensorsConnected(in SensorInfo[] sensorInfos);

    /**
     * Notify the framework that previously connected dynamic sensors have been
     * disconnected.
     *
     * If a dynamic sensor was previously disconnected and has not been
     * reconnected, then that sensor must not be included in sensorHandles.
     *
     * The HAL must ensure that all sensor events from departing dynamic
     * sensors have been written to the Event FMQ before calling
     * onDynamicSensorsDisconnected.
     *
     * @param sensorHandles vector of sensor handles for each dynamic sensors
     *     that was disconnected.
     */
    void onDynamicSensorsDisconnected(in int[] sensorHandles);
}
