// xenoid_sensors_hal.cpp — virtual AIDL sensor HAL with a real FMQ event stream.
// SensorService owns the queue; this service maps the supplied descriptor and
// writes fixed-size Event records using the synchronized FMQ memory protocol.
#include "sensor_catalog.h"
#include <android/binder_status.h>
#include <android/log.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <thread>
#include <unordered_map>
#include <unistd.h>
#include <vector>

// The NDK omits service-side binder declarations, but libbinder_ndk exports them.
struct AIBinder;
extern "C" {
binder_status_t AServiceManager_addService(AIBinder* binder, const char* instance);
void ABinderProcess_startThreadPool(void);
void ABinderProcess_joinThreadPool(void);
}
#include "aidl/android/hardware/sensors/BnSensors.h"
#include "aidl/android/hardware/sensors/SensorInfo.h"
#include "aidl/android/hardware/sensors/SensorStatus.h"
#include "aidl/android/hardware/sensors/SensorType.h"

using ::ndk::ScopedAStatus;
using ::ndk::SharedRefBase;
using aidl::android::hardware::sensors::SensorInfo;
using aidl::android::hardware::sensors::SensorType;
using aidl::android::hardware::sensors::ISensors;
using aidl::android::hardware::sensors::ISensorsCallback;

namespace {

SensorInfo mk(int handle, const char* name, const char* vendor, SensorType type,
              const char* typeStr, float maxRange, float resolution, float power,
              int minDelayUs, int maxDelayUs, int flags) {
  SensorInfo sensor;
  sensor.sensorHandle = handle;
  sensor.name = name;
  sensor.vendor = vendor;
  sensor.version = 1;
  sensor.type = type;
  sensor.typeAsString = typeStr;
  sensor.maxRange = maxRange;
  sensor.resolution = resolution;
  sensor.power = power;
  sensor.minDelayUs = minDelayUs;
  sensor.fifoReservedEventCount = 0;
  sensor.fifoMaxEventCount = 10000;
  sensor.requiredPermission = "";
  sensor.maxDelayUs = maxDelayUs;
  sensor.flags = flags;
  return sensor;
}

std::vector<SensorInfo> buildCatalog() {
  size_t count = 0;
  const XenoidSensorSpec* specs = xenoid_sensor_catalog(&count);
  std::vector<SensorInfo> catalog;
  catalog.reserve(count);
  for (size_t index = 0; index < count; index++) {
    const XenoidSensorSpec& spec = specs[index];
    catalog.push_back(mk(
        spec.handle, spec.name, spec.vendor, static_cast<SensorType>(spec.type),
        spec.type_string, spec.maximum_range, spec.resolution, spec.power_ma,
        spec.minimum_delay_us, spec.maximum_delay_us, spec.flags));
  }
  return catalog;
}

class XenoidSensorsHal : public aidl::android::hardware::sensors::BnSensors {
 public:
  using Event = aidl::android::hardware::sensors::Event;
  using EventDescriptor = ::aidl::android::hardware::common::fmq::MQDescriptor<
      Event, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>;

  ~XenoidSensorsHal() override {
    stopWorker();
    std::lock_guard<std::mutex> lock(mu_);
    clearMappingsLocked();
  }

  ScopedAStatus getSensorsList(std::vector<SensorInfo>* out) override {
    *out = buildCatalog();
    __android_log_print(ANDROID_LOG_INFO, "xenoid-sensors",
                        "getSensorsList -> %zu sensors", out->size());
    return ScopedAStatus::ok();
  }

  ScopedAStatus initialize(
      const EventDescriptor& eventDescriptor,
      const ::aidl::android::hardware::common::fmq::MQDescriptor<
          int32_t, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>&,
      const std::shared_ptr<ISensorsCallback>&) override {
    stopWorker();
    {
      std::lock_guard<std::mutex> lock(mu_);
      clearMappingsLocked();
      if (!mapEventQueueLocked(eventDescriptor)) {
        __android_log_print(ANDROID_LOG_ERROR, "xenoid-sensors",
                            "invalid event FMQ descriptor");
        return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
      }
      active_.clear();
      periods_.clear();
    }
    running_.store(true, std::memory_order_release);
    worker_ = std::thread(&XenoidSensorsHal::workerLoop, this);
    __android_log_print(ANDROID_LOG_INFO, "xenoid-sensors",
                        "event FMQ ready: capacity=%zu", capacity_);
    return ScopedAStatus::ok();
  }

  ScopedAStatus activate(int32_t handle, bool enabled) override {
    const SensorInfo* info = findSensor(handle);
    if (info == nullptr) return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    std::lock_guard<std::mutex> lock(mu_);
    if (enabled) {
      int64_t period = periods_.count(handle) ? periods_[handle]
                                             : std::max<int64_t>(info->minDelayUs * 1000LL, 20000000LL);
      // Decoded reporting mode: (flags & 0xE) >> 1; ON_CHANGE(1) must not stream.
      const int mode = (info->flags & 0xE) >> 1;
      if (mode == 1) period = std::max<int64_t>(period, 1000000000LL);
      active_[handle] = {period, 0};
      if (mode == 2) {
        Event event = makeEvent(*info, bootTimeNs());
        writeEventLocked(event);
        active_.erase(handle);
      }
    } else {
      active_.erase(handle);
    }
    return ScopedAStatus::ok();
  }

  ScopedAStatus batch(
      int32_t handle, int64_t samplingPeriodNs,
      int64_t maxReportLatencyNs) override {
    const SensorInfo* info = findSensor(handle);
    if (info == nullptr
        || !xenoid_sensor_period_valid(
            info->minDelayUs, info->maxDelayUs, samplingPeriodNs,
            maxReportLatencyNs)) {
      return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    }
    std::lock_guard<std::mutex> lock(mu_);
    periods_[handle] = samplingPeriodNs;
    auto it = active_.find(handle);
    if (it != active_.end()) it->second.periodNs = samplingPeriodNs;
    return ScopedAStatus::ok();
  }

  ScopedAStatus flush(int32_t handle) override {
    if (findSensor(handle) == nullptr) {
      return ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    }
    Event event;
    event.timestamp = bootTimeNs();
    event.sensorHandle = handle;
    event.sensorType = SensorType::META_DATA;
    Event::EventPayload::MetaData meta;
    meta.what = Event::EventPayload::MetaData::MetaDataEventType::META_DATA_FLUSH_COMPLETE;
    event.payload.set<Event::EventPayload::meta>(meta);
    std::lock_guard<std::mutex> lock(mu_);
    return writeEventLocked(event) ? ScopedAStatus::ok()
                                   : ScopedAStatus::fromServiceSpecificError(EAGAIN);
  }

  ScopedAStatus injectSensorData(const Event& event) override {
    return writeEventLocked(event) ? ScopedAStatus::ok()
                                   : ScopedAStatus::fromServiceSpecificError(EAGAIN);
  }

  ScopedAStatus configDirectReport(int32_t, int32_t, ISensors::RateLevel,
                                   int32_t* out) override {
    *out = -1;
    return ScopedAStatus::ok();
  }
  ScopedAStatus registerDirectChannel(const ISensors::SharedMemInfo&, int32_t* out) override {
    *out = -1;
    return ScopedAStatus::ok();
  }
  ScopedAStatus unregisterDirectChannel(int32_t) override { return ScopedAStatus::ok(); }
  ScopedAStatus setOperationMode(ISensors::OperationMode) override {
    return ScopedAStatus::ok();
  }

 private:
  struct Mapping {
    void* base = MAP_FAILED;
    size_t length = 0;
    uint8_t* address = nullptr;
  };
  struct ActiveSensor {
    int64_t periodNs;
    int64_t nextNs;
  };

  static int64_t bootTimeNs() {
    timespec ts{};
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return static_cast<int64_t>(ts.tv_sec) * 1000000000LL + ts.tv_nsec;
  }

  static const SensorInfo* findSensor(int32_t handle) {
    static const std::vector<SensorInfo> catalog = buildCatalog();
    for (const auto& sensor : catalog) {
      if (sensor.sensorHandle == handle) return &sensor;
    }
    return nullptr;
  }

  bool mapEventQueueLocked(const EventDescriptor& descriptor) {
    if (descriptor.grantors.size() < 4 || descriptor.quantum != sizeof(Event) ||
        descriptor.handle.fds.empty()) {
      return false;
    }
    mappings_.reserve(4);
    for (size_t index = 0; index < 4; ++index) {
      const auto& grantor = descriptor.grantors[index];
      if (grantor.fdIndex < 0 ||
          static_cast<size_t>(grantor.fdIndex) >= descriptor.handle.fds.size() ||
          grantor.offset < 0 || grantor.extent <= 0) {
        clearMappingsLocked();
        return false;
      }
      const long pageSize = sysconf(_SC_PAGESIZE);
      const off_t mapOffset = static_cast<off_t>(grantor.offset) & ~(pageSize - 1);
      const size_t delta = static_cast<size_t>(grantor.offset - mapOffset);
      const size_t mapLength = delta + static_cast<size_t>(grantor.extent);
      void* base = mmap(nullptr, mapLength, PROT_READ | PROT_WRITE, MAP_SHARED,
                        descriptor.handle.fds[grantor.fdIndex].get(), mapOffset);
      if (base == MAP_FAILED) {
        clearMappingsLocked();
        return false;
      }
      mappings_.push_back({base, mapLength, static_cast<uint8_t*>(base) + delta});
    }
    readPosition_ = reinterpret_cast<std::atomic<uint64_t>*>(mappings_[0].address);
    writePosition_ = reinterpret_cast<std::atomic<uint64_t>*>(mappings_[1].address);
    ring_ = mappings_[2].address;
    eventFlag_ = reinterpret_cast<std::atomic<uint32_t>*>(mappings_[3].address);
    capacity_ = static_cast<size_t>(descriptor.grantors[2].extent) / sizeof(Event);
    return capacity_ > 0;
  }

  void clearMappingsLocked() {
    for (const auto& mapping : mappings_) {
      if (mapping.base != MAP_FAILED) munmap(mapping.base, mapping.length);
    }
    mappings_.clear();
    readPosition_ = nullptr;
    writePosition_ = nullptr;
    ring_ = nullptr;
    eventFlag_ = nullptr;
    capacity_ = 0;
  }

  bool writeEventLocked(const Event& event) {
    if (readPosition_ == nullptr || writePosition_ == nullptr || ring_ == nullptr ||
        eventFlag_ == nullptr || capacity_ == 0) {
      return false;
    }
    const uint64_t read = readPosition_->load(std::memory_order_acquire);
    const uint64_t write = writePosition_->load(std::memory_order_relaxed);
    const size_t ringBytes = capacity_ * sizeof(Event);
    if (write < read || write % sizeof(Event) != 0 ||
        write - read + sizeof(Event) > ringBytes) {
      return false;
    }
    std::memcpy(ring_ + (write % ringBytes), &event, sizeof(Event));
    writePosition_->store(write + sizeof(Event), std::memory_order_release);
    constexpr uint32_t notification = ISensors::EVENT_QUEUE_FLAG_BITS_READ_AND_PROCESS;
    const uint32_t oldFlags = eventFlag_->fetch_or(notification, std::memory_order_release);
    if ((~oldFlags & notification) != 0) {
      syscall(__NR_futex, reinterpret_cast<int32_t*>(eventFlag_), FUTEX_WAKE_BITSET,
              INT_MAX, nullptr, nullptr, notification);
    }
    return true;
  }

  static Event makeEvent(const SensorInfo& sensor, int64_t nowNs) {
    using Payload = Event::EventPayload;
    const double t = static_cast<double>(nowNs) / 1000000000.0;
    Event event;
    event.timestamp = nowNs;
    event.sensorHandle = sensor.sensorHandle;
    event.sensorType = sensor.type;
    const float a = static_cast<float>(std::sin(t * 0.83));
    const float b = static_cast<float>(std::sin(t * 0.47 + 1.3));
    const float c = static_cast<float>(std::sin(t * 0.31 + 2.1));

    switch (sensor.type) {
      case SensorType::ACCELEROMETER:
      case SensorType::GRAVITY:
      case SensorType::LINEAR_ACCELERATION:
      case SensorType::GYROSCOPE:
      case SensorType::MAGNETIC_FIELD:
      case SensorType::ORIENTATION: {
        Payload::Vec3 value;
        value.status = aidl::android::hardware::sensors::SensorStatus::ACCURACY_HIGH;
        if (sensor.type == SensorType::ACCELEROMETER) {
          value.x = 0.018f * a; value.y = 0.015f * b; value.z = 9.80665f + 0.012f * c;
        } else if (sensor.type == SensorType::GRAVITY) {
          value.x = 0.005f * a; value.y = 0.004f * b; value.z = 9.80665f;
        } else if (sensor.type == SensorType::LINEAR_ACCELERATION) {
          value.x = 0.013f * a; value.y = 0.011f * b; value.z = 0.012f * c;
        } else if (sensor.type == SensorType::GYROSCOPE) {
          value.x = 0.0014f * a; value.y = 0.0011f * b; value.z = 0.0013f * c;
        } else if (sensor.type == SensorType::MAGNETIC_FIELD) {
          value.x = 19.8f + 0.08f * a; value.y = -5.4f + 0.07f * b; value.z = 43.1f + 0.09f * c;
        } else {
          value.x = 1.0f + 0.03f * a; value.y = 0.3f + 0.02f * b; value.z = 0.0f;
        }
        event.payload.set<Payload::vec3>(value);
        break;
      }
      case SensorType::ACCELEROMETER_UNCALIBRATED:
      case SensorType::GYROSCOPE_UNCALIBRATED:
      case SensorType::MAGNETIC_FIELD_UNCALIBRATED: {
        Payload::Uncal value;
        const float scale = sensor.type == SensorType::MAGNETIC_FIELD_UNCALIBRATED ? 20.0f : 0.002f;
        value.x = scale + 0.01f * a; value.y = -0.2f * scale + 0.01f * b;
        value.z = 2.1f * scale + 0.01f * c;
        value.xBias = 0.0003f; value.yBias = -0.0002f; value.zBias = 0.0001f;
        event.payload.set<Payload::uncal>(value);
        break;
      }
      case SensorType::GAME_ROTATION_VECTOR: {
        Payload::Vec4 value;
        value.x = 0.001f * a; value.y = 0.001f * b; value.z = 0.003f * c;
        value.w = 0.99999f;
        event.payload.set<Payload::vec4>(value);
        break;
      }
      case SensorType::ROTATION_VECTOR:
      case SensorType::GEOMAGNETIC_ROTATION_VECTOR: {
        // Android 14 AOSP convertToSensorEvent(): only GAME_ROTATION_VECTOR maps
        // to vec4; ROTATION/GEOMAGNETIC go through payload.get<data>() (16-float
        // Data, first five entries x/y/z/w/headingAccuracy). A wrong union tag
        // aborts system_server in AidlSensorHalWrapper::pollFmq (observed).
        Payload::Data value{};
        value.values[0] = 0.001f * a;
        value.values[1] = 0.001f * b;
        value.values[2] = 0.003f * c;
        value.values[3] = 0.99999f;
        value.values[4] = 0.0f;
        event.payload.set<Payload::data>(value);
        break;
      }
      case SensorType::STEP_COUNTER:
        event.payload.set<Payload::stepCount>(static_cast<int64_t>(t / 1.7));
        break;
      default: {
        float sample = 0.0f;
        if (xenoid_sensor_scalar_sample(
                static_cast<int32_t>(sensor.type), t, &sample) != 0) {
          sample = 0.0f;
        }
        if (static_cast<int32_t>(sensor.type) >=
            static_cast<int32_t>(SensorType::DEVICE_PRIVATE_BASE)) {
          Payload::Data value{};
          value.values[0] = sample;
          event.payload.set<Payload::data>(value);
        } else {
          event.payload.set<Payload::scalar>(sample);
        }
        break;
      }
    }
    return event;
  }

  void workerLoop() {
    while (running_.load(std::memory_order_acquire)) {
      const int64_t now = bootTimeNs();
      {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& entry : active_) {
          ActiveSensor& state = entry.second;
          if (state.nextNs == 0 || now >= state.nextNs) {
            const SensorInfo* sensor = findSensor(entry.first);
            if (sensor != nullptr) writeEventLocked(makeEvent(*sensor, now));
            state.nextNs = now + state.periodNs;
          }
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
  }

  void stopWorker() {
    running_.store(false, std::memory_order_release);
    if (worker_.joinable()) worker_.join();
  }

  std::mutex mu_;
  std::vector<Mapping> mappings_;
  std::unordered_map<int32_t, ActiveSensor> active_;
  std::unordered_map<int32_t, int64_t> periods_;
  std::atomic<bool> running_{false};
  std::thread worker_;
  std::atomic<uint64_t>* readPosition_ = nullptr;
  std::atomic<uint64_t>* writePosition_ = nullptr;
  std::atomic<uint32_t>* eventFlag_ = nullptr;
  uint8_t* ring_ = nullptr;
  size_t capacity_ = 0;
};

}  // namespace

int main() {
  __android_log_print(4, "xenoid-sensors", "starting virtual sensor HAL");
  std::shared_ptr<XenoidSensorsHal> svc = SharedRefBase::make<XenoidSensorsHal>();
  const char* name = "android.hardware.sensors.ISensors/default";
  binder_status_t st = AServiceManager_addService(svc->asBinder().get(), name);
  if (st != STATUS_OK) {
    __android_log_print(6, "xenoid-sensors", "addService failed: %d", st);
    return 1;
  }
  __android_log_print(4, "xenoid-sensors", "registered %s", name);
  ABinderProcess_startThreadPool();
  ABinderProcess_joinThreadPool();
  return 0;
}
