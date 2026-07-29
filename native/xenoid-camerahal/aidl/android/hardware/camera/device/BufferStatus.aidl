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
 * BufferStatus:
 *
 * The current status of a single stream buffer.
 */
@VintfStability
@Backing(type="int")
enum BufferStatus {
    /**
     * The buffer is in a normal state, and can be used after waiting on its
     * sync fence.
     */
    OK = 0,

    /**
     * The buffer does not contain valid data, and the data in it must not be
     * used. The sync fence must still be waited on before reusing the buffer.
     */
    ERROR = 1,
}
