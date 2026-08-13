#ifndef XENOID_POWER_SUPPLY_H
#define XENOID_POWER_SUPPLY_H

#include <stddef.h>

#define XENOID_BATTERY_FILE_COUNT 14
#define XENOID_BATTERY_VALUE_MAX 768

struct xenoid_battery_profile {
  long level;
  long scale;
  long voltage_mv;
  long temperature_deci_c;
  long status;
  long plugged;
  long health;
  long present;
  const char *technology;
  long capacity_mah;
  long minimum_capacity_mah;
  long charge_full_design_uah;
  long charge_full_uah;
  long charge_counter_uah;
};

struct xenoid_battery_file {
  const char *name;
  char value[XENOID_BATTERY_VALUE_MAX];
};

int xenoid_render_battery_files(
    const struct xenoid_battery_profile *profile,
    struct xenoid_battery_file *files,
    size_t count);

#endif
