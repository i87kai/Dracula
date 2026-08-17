#include "core/virtual_time.h"

namespace Dracula {

    VirtualTimeState::VirtualTimeState(const TimingPolicy& policy) : m_policy(policy) {}

    void VirtualTimeState::SetPolicy(const TimingPolicy& policy) {
        m_policy = policy;
        Reset();
    }

    void VirtualTimeState::Reset() {
        m_nanos = 0;
        m_events.clear();
    }

    void VirtualTimeState::OnInstructionsRetired(uint64_t count) {
        if (m_policy.nanosPerInstruction == 0 || count == 0) return;
        m_nanos += m_policy.nanosPerInstruction * count;
    }

    void VirtualTimeState::AdvanceNanos(uint64_t nanos, const std::string& reason,
                                        const std::string& source) {
        if (nanos == 0) return;
        if (m_events.size() < kMaxAdvanceEvents) {
            m_events.push_back({m_nanos, nanos, reason, source});
        }
        m_nanos += nanos;
    }

    void VirtualTimeState::AdvanceMillis(uint64_t millis, const std::string& reason,
                                         const std::string& source) {
        AdvanceNanos(millis * 1000000ULL, reason, source);
    }

    // Every source below reads the same m_nanos. There is no second counter
    // that could drift away from it.

    uint64_t VirtualTimeState::Tsc() const {
        // nanos * tscHz / 1e9, ordered to avoid overflow on long runs.
        const uint64_t seconds = m_nanos / 1000000000ULL;
        const uint64_t remainder = m_nanos % 1000000000ULL;
        return m_policy.tscBase + seconds * m_policy.tscHz +
               (remainder * m_policy.tscHz) / 1000000000ULL;
    }

    uint64_t VirtualTimeState::QpcCounter() const {
        const uint64_t seconds = m_nanos / 1000000000ULL;
        const uint64_t remainder = m_nanos % 1000000000ULL;
        return seconds * m_policy.qpcHz + (remainder * m_policy.qpcHz) / 1000000000ULL;
    }

    uint64_t VirtualTimeState::ElapsedMillis() const {
        return m_nanos / 1000000ULL;
    }

    uint64_t VirtualTimeState::TickCount64() const {
        return m_policy.tickCountBaseMs + ElapsedMillis();
    }

    uint32_t VirtualTimeState::TickCount32() const {
        return static_cast<uint32_t>(TickCount64() & 0xFFFFFFFFULL);
    }

    uint64_t VirtualTimeState::UptimeMillis() const {
        return m_policy.bootUptimeMs + ElapsedMillis();
    }

    uint32_t EnvironmentRuntime::Observe(const std::string& source,
                                         const std::string& property,
                                         uint64_t address, uint64_t rva,
                                         uint64_t inputValue,
                                         const std::string& supplied,
                                         const std::string& baselineValue) {
        for (size_t i = 0; i < observations.size(); ++i) {
            auto& o = observations[i];
            if (o.address == address && o.property == property && o.inputValue == inputValue) {
                o.occurrences++;
                return static_cast<uint32_t>(i);
            }
        }
        if (observations.size() >= kMaxObservations) {
            return static_cast<uint32_t>(observations.size() ? observations.size() - 1 : 0);
        }

        EnvironmentObservation o;
        o.source = source;
        o.property = property;
        o.address = address;
        o.rva = rva;
        o.inputValue = inputValue;
        o.suppliedValue = supplied;
        o.baselineValue = baselineValue;
        o.normalized = (supplied != baselineValue);
        o.profile = profile.name;
        observations.push_back(o);
        return static_cast<uint32_t>(observations.size() - 1);
    }

} // namespace Dracula
