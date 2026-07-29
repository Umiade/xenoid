/*
 * Copyright (C) 2022 The Android Open Source Project
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

package android.hardware.camera.device;

/**
 * ShutterMsg:
 *
 * Message contents for MsgType::SHUTTER
 */
@VintfStability
parcelable ShutterMsg {
    /**
     * Frame number of the request that has begun exposure or reprocessing.
     */
    int frameNumber;

    /**
     * Timestamp for the start of capture. For a reprocess request, this must
     * be input image's start of capture. This must match the capture result
     * metadata's sensor exposure start timestamp.
     */
    long timestamp;

    /**
     * Timestamp for the capture readout. This must be in the same time domain
     * as timestamp, and for a rolling shutter sensor, the value must be
     * timestamp + exposureTime + t_crop_top where t_crop_top is the exposure time
     * skew of the cropped lines on the top.
     */
    long readoutTimestamp;
}
