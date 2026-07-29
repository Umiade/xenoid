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

import android.hardware.camera.device.ErrorCode;

/**
 * ErrorMsg:
 *
 * Message contents for MsgType::ERROR
 */
@VintfStability
parcelable ErrorMsg {
    /**
     * Frame number of the request the error applies to. 0 if the frame number
     * isn't applicable to the error.
     */
    int frameNumber;

    /**
     * Pointer to the stream that had a failure. -1 if the stream isn't
     * applicable to the error.
     */
    int errorStreamId;

    /**
     * The code for this error.
     */
    ErrorCode errorCode;
}
