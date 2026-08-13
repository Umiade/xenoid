#include "xenoid_power_supply.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static const char *status_text(long status) {
  switch (status) {
    case 1: return "Unknown";
    case 2: return "Charging";
    case 3: return "Discharging";
    case 4: return "Not charging";
    case 5: return "Full";
    default: return NULL;
  }
}

static const char *health_text(long health) {
  switch (health) {
    case 1: return "Unknown";
    case 2: return "Good";
    case 3: return "Overheat";
    case 4: return "Dead";
    case 5: return "Over voltage";
    case 6: return "Unspecified failure";
    case 7: return "Cold";
    default: return NULL;
  }
}

static const char *capacity_level_text(long level) {
  if (level <= 5) return "Critical";
  if (level <= 15) return "Low";
  if (level >= 100) return "Full";
  if (level >= 90) return "High";
  return "Normal";
}

static int set_file(
    struct xenoid_battery_file *file,
    const char *name,
    const char *format,
    long value) {
  file->name = name;
  int written = snprintf(file->value, sizeof(file->value), format, value);
  return written < 0 || (size_t)written >= sizeof(file->value) ? -1 : 0;
}

static int set_text(
    struct xenoid_battery_file *file,
    const char *name,
    const char *value) {
  file->name = name;
  int written = snprintf(file->value, sizeof(file->value), "%s\n", value);
  return written < 0 || (size_t)written >= sizeof(file->value) ? -1 : 0;
}

int xenoid_render_battery_files(
    const struct xenoid_battery_profile *profile,
    struct xenoid_battery_file *files,
    size_t count) {
  if (profile == NULL || files == NULL || count < XENOID_BATTERY_FILE_COUNT) {
    errno = EINVAL;
    return -1;
  }
  const char *status = status_text(profile->status);
  const char *health = health_text(profile->health);
  const char *technology = profile->technology;
  int plugged_valid = profile->plugged == 0 || profile->plugged == 1
      || profile->plugged == 2 || profile->plugged == 4;
  int state_valid = !((profile->plugged == 0 && profile->status == 2)
      || (profile->plugged != 0 && profile->status == 3));
  size_t technology_length = technology == NULL ? 0 : strlen(technology);
  if (profile->scale != 100 || profile->level < 0 || profile->level > 100
      || profile->voltage_mv < 1000 || profile->voltage_mv > 6000
      || profile->temperature_deci_c < -500 || profile->temperature_deci_c > 1000
      || status == NULL || health == NULL || !plugged_valid || !state_valid
      || (profile->present != 0 && profile->present != 1)
      || technology_length == 0 || technology_length > 32
      || strchr(technology, '\n') != NULL || strchr(technology, '\r') != NULL
      || profile->capacity_mah <= 0 || profile->minimum_capacity_mah <= 0
      || profile->minimum_capacity_mah > profile->capacity_mah
      || profile->capacity_mah > 100000
      || profile->charge_full_design_uah != profile->capacity_mah * 1000
      || profile->charge_full_uah <= 0
      || profile->charge_full_uah > profile->charge_full_design_uah
      || profile->charge_counter_uah < 0
      || profile->charge_counter_uah
          != profile->charge_full_uah * profile->level / profile->scale) {
    errno = EINVAL;
    return -1;
  }

  size_t index = 0;
  if (set_file(&files[index++], "capacity", "%ld\n", profile->level)
      || set_text(&files[index++], "status", status)
      || set_text(&files[index++], "health", health)
      || set_file(&files[index++], "present", "%ld\n", profile->present)
      || set_file(&files[index++], "temp", "%ld\n", profile->temperature_deci_c)
      || set_file(&files[index++], "voltage_now", "%ld\n", profile->voltage_mv * 1000)
      || set_text(&files[index++], "technology", technology)
      || set_text(&files[index++], "capacity_level", capacity_level_text(profile->level))
      || set_file(&files[index++], "charge_full_design", "%ld\n", profile->charge_full_design_uah)
      || set_file(&files[index++], "charge_full", "%ld\n", profile->charge_full_uah)
      || set_file(&files[index++], "charge_counter", "%ld\n", profile->charge_counter_uah)
      || set_text(&files[index++], "type", "Battery")
      || set_file(&files[index++], "online", "%ld\n", profile->present)) {
    errno = EOVERFLOW;
    return -1;
  }

  struct xenoid_battery_file *uevent = &files[index++];
  uevent->name = "uevent";
  int written = snprintf(
      uevent->value,
      sizeof(uevent->value),
      "POWER_SUPPLY_NAME=battery\n"
      "POWER_SUPPLY_TYPE=Battery\n"
      "POWER_SUPPLY_STATUS=%s\n"
      "POWER_SUPPLY_HEALTH=%s\n"
      "POWER_SUPPLY_PRESENT=%ld\n"
      "POWER_SUPPLY_TECHNOLOGY=%s\n"
      "POWER_SUPPLY_CAPACITY=%ld\n"
      "POWER_SUPPLY_CAPACITY_LEVEL=%s\n"
      "POWER_SUPPLY_VOLTAGE_NOW=%ld\n"
      "POWER_SUPPLY_CHARGE_FULL_DESIGN=%ld\n"
      "POWER_SUPPLY_CHARGE_FULL=%ld\n"
      "POWER_SUPPLY_CHARGE_COUNTER=%ld\n"
      "POWER_SUPPLY_TEMP=%ld\n",
      status,
      health,
      profile->present,
      technology,
      profile->level,
      capacity_level_text(profile->level),
      profile->voltage_mv * 1000,
      profile->charge_full_design_uah,
      profile->charge_full_uah,
      profile->charge_counter_uah,
      profile->temperature_deci_c);
  if (written < 0 || (size_t)written >= sizeof(uevent->value)
      || index != XENOID_BATTERY_FILE_COUNT) {
    errno = EOVERFLOW;
    return -1;
  }
  return 0;
}
