#ifndef XENOID_SENSOR_CATALOG_H
#define XENOID_SENSOR_CATALOG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct XenoidSensorSpec {
  int32_t handle;
  int32_t type;
  const char *type_string;
  const char *name;
  const char *vendor;
  int32_t version;
  float maximum_range;
  float resolution;
  float power_ma;
  int32_t minimum_delay_us;
  int32_t maximum_delay_us;
  int32_t flags;
};

const struct XenoidSensorSpec *xenoid_sensor_catalog(size_t *count);
int xenoid_sensor_scalar_sample(int32_t type, double seconds, float *value);

int xenoid_sensor_period_valid(
    int32_t minimum_delay_us,
    int32_t maximum_delay_us,
    int64_t sampling_period_ns,
    int64_t max_report_latency_ns);

#ifdef __cplusplus
}
#endif

#endif
