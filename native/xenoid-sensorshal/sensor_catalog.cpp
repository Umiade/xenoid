#include "sensor_catalog.h"

#include <cmath>

namespace {

constexpr XenoidSensorSpec kCatalog[] = {
    {1, 1, "android.sensor.accelerometer", "LSM6DSR Accelerometer",
     "STMicroelectronics", 1, 78.4532f, 0.00239563f, 0.24f, 5000, 200000, 0},
    {2, 4, "android.sensor.gyroscope", "LSM6DSR Gyroscope",
     "STMicroelectronics", 1, 34.9066f, 0.00122173f, 0.55f, 5000, 200000, 0},
    {3, 2, "android.sensor.magnetic_field", "MMC56X3X Magnetometer",
     "MEMSIC", 1, 3000.0f, 0.1f, 0.2f, 10000, 200000, 0},
    {4, 8, "android.sensor.proximity", "TMD3719 Proximity",
     "ams AG", 1, 5.0f, 1.0f, 0.13f, 0, 0, 2},
    {5, 5, "android.sensor.light", "TMD3719 Light",
     "ams AG", 1, 12000.0f, 1.0f, 0.13f, 0, 0, 2},
    {6, 6, "android.sensor.pressure", "ICP10101 Pressure",
     "TDK InvenSense", 1, 1100.0f, 0.0002f, 0.02f, 50000, 1000000, 0},
    {7, 35, "android.sensor.accelerometer_uncalibrated",
     "LSM6DSR Accelerometer Uncalibrated", "STMicroelectronics", 1,
     78.4532f, 0.00239563f, 0.24f, 5000, 200000, 0},
    {8, 16, "android.sensor.gyroscope_uncalibrated",
     "LSM6DSR Gyroscope Uncalibrated", "STMicroelectronics", 1,
     34.9066f, 0.00122173f, 0.55f, 5000, 200000, 0},
    {9, 14, "android.sensor.magnetic_field_uncalibrated",
     "MMC56X3X Magnetometer Uncalibrated", "MEMSIC", 1,
     3000.0f, 0.1f, 0.2f, 10000, 200000, 0},
    {10, 19, "android.sensor.step_counter", "CHRE Step Counter",
     "Google LLC", 1, 1.0f, 1.0f, 0.0f, 0, 0, 2},
    {11, 18, "android.sensor.step_detector", "CHRE Step Detector",
     "Google LLC", 1, 1.0f, 1.0f, 0.0f, 0, 0, 6},
    {13, 15, "android.sensor.game_rotation_vector",
     "CHRE Game Rotation Vector", "Google LLC", 1,
     1.0f, 1.0f, 0.0f, 5000, 200000, 0},
    {14, 20, "android.sensor.geomagnetic_rotation_vector",
     "CHRE Geomagnetic Rotation Vector", "Google LLC", 1,
     1.0f, 1.0f, 0.0f, 10000, 200000, 0},
    {15, 9, "android.sensor.gravity", "CHRE Gravity",
     "Google LLC", 1, 9.80665f, 0.001f, 0.0f, 10000, 200000, 0},
    {16, 10, "android.sensor.linear_acceleration",
     "CHRE Linear Acceleration", "Google LLC", 1,
     78.4532f, 0.00239563f, 0.0f, 5000, 200000, 0},
    {17, 11, "android.sensor.rotation_vector", "CHRE Rotation Vector",
     "Google LLC", 1, 1.0f, 1.0f, 0.0f, 5000, 200000, 0},
    {18, 3, "android.sensor.orientation", "CHRE Orientation",
     "Google LLC", 1, 360.0f, 0.01f, 0.0f, 10000, 200000, 0},
    {19, 65545, "com.google.sensor.rear_light", "VD6282 Rear Light Sensor",
     "STMicroelectronics", 1, 65535.0f, 1.0f, 0.13f, 0, 0, 2},
};

}  // namespace

extern "C" const XenoidSensorSpec *xenoid_sensor_catalog(size_t *count) {
  if (count != nullptr) *count = sizeof(kCatalog) / sizeof(kCatalog[0]);
  return kCatalog;
}

extern "C" int xenoid_sensor_scalar_sample(
    int32_t type, double seconds, float *value) {
  if (value == nullptr || !std::isfinite(seconds)) return -1;
  const float wave = static_cast<float>(std::sin(seconds * 0.83));
  switch (type) {
    case 5:
      *value = 74.0f + 2.0f * wave;
      return 0;
    case 6:
      *value = 1008.2f + 0.03f * wave;
      return 0;
    case 8:
      *value = 5.0f;
      return 0;
    case 18:
      *value = 1.0f;
      return 0;
    case 65545:
      *value = 48.0f + 4.0f * wave;
      return 0;
    default:
      return -1;
  }
}

extern "C" int xenoid_sensor_period_valid(
    int32_t minimum_delay_us,
    int32_t maximum_delay_us,
    int64_t sampling_period_ns,
    int64_t max_report_latency_ns) {
  if (minimum_delay_us < 0 || maximum_delay_us < 0
      || (maximum_delay_us > 0 && maximum_delay_us < minimum_delay_us)
      || sampling_period_ns <= 0 || max_report_latency_ns < 0) {
    return 0;
  }
  const int64_t minimum_ns =
      static_cast<int64_t>(minimum_delay_us) * 1000LL;
  const int64_t maximum_ns =
      static_cast<int64_t>(maximum_delay_us) * 1000LL;
  if ((minimum_ns > 0 && sampling_period_ns < minimum_ns)
      || (maximum_ns > 0 && sampling_period_ns > maximum_ns)) {
    return 0;
  }
  return 1;
}
