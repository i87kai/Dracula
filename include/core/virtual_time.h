#pragma once

//
// Dracula coherent virtual clock.
//
// Sophisticated samples do not read one clock, they read several and compare
// them. An analysis environment that advances GetTickCount by 5000 ms while
// RDTSC advances by two cycles has told the sample exactly what it is.
//
// VirtualTimeState therefore keeps exactly ONE authoritative quantity, a
// logical nanosecond counter, and derives every exposed clock from it:
//
//        logical nanoseconds
//        ├── RDTSC / RDTSCP        nanos * tscHz  / 1e9  + tscBase
//        ├── QueryPerformanceCounter  nanos * qpcHz / 1e9
//        ├── GetTickCount / GetTickCount64   nanos / 1e6 + tickBase
//        └── GetSystemTimes uptime    nanos / 1e6 + bootUptime
//
// Because there is only one counter, the clocks cannot disagree. Advancing time
// (an instruction retiring, or an accelerated Sleep) advances all of them at
// once, by construction.
//

#include "core/environment_profile.h"
#include <string>
#include <vector>
#include <cstdint>

namespace Dracula {

    // A recorded moment where Dracula advanced logical time by something other
    // than instruction retirement, e.g. an accelerated Sleep.
    struct TimeAdvanceEvent {
        uint64_t    atNanos = 0;      // logical time before the advance
        uint64_t    byNanos = 0;      // how much was added
        std::string reason;           // "Sleep(5000) accelerated"
        std::string source;           // "kernel32!Sleep"
    };

    class VirtualTimeState {
    public:
        VirtualTimeState() : VirtualTimeState(TimingPolicy{}) {}
        explicit VirtualTimeState(const TimingPolicy& policy);

        void SetPolicy(const TimingPolicy& policy);
        const TimingPolicy& Policy() const { return m_policy; }

        void Reset();

        // Charge one (or several) retired instructions against the clock.
        void OnInstructionsRetired(uint64_t count = 1);

        // Advance logical time explicitly. Used by accelerated sleeps and by
        // any modelled operation whose duration matters to the sample.
        void AdvanceMillis(uint64_t millis, const std::string& reason,
                           const std::string& source);
        void AdvanceNanos(uint64_t nanos, const std::string& reason,
                          const std::string& source);

        // ─── Derived clock sources (all consistent by construction) ─────────
        uint64_t Nanos() const { return m_nanos; }
        uint64_t Tsc() const;
        uint64_t TickCount64() const;
        uint32_t TickCount32() const;
        uint64_t QpcCounter() const;
        uint64_t QpcFrequency() const { return m_policy.qpcHz; }
        uint64_t UptimeMillis() const;
        uint64_t ElapsedMillis() const;

        // Every explicit advance, in order. Reported as evidence so an analyst
        // can see exactly where Dracula moved the clock.
        const std::vector<TimeAdvanceEvent>& AdvanceEvents() const { return m_events; }

        // True when logical time was advanced by anything other than retiring
        // instructions, i.e. the run contains normalized timing.
        bool WasNormalized() const { return !m_events.empty(); }

    private:
        TimingPolicy                  m_policy;
        uint64_t                      m_nanos = 0;
        std::vector<TimeAdvanceEvent> m_events;

        static constexpr size_t kMaxAdvanceEvents = 256;
    };

    // ─── Shared environment runtime ─────────────────────────────────────────
    //
    // The one object that instruction-level interception (CPUID, RDTSC) and the
    // Win32 HLE layer both consult, so a sample cannot get two different answers
    // about the same machine depending on which door it knocked on.

    struct EnvironmentRuntime {
        EnvironmentProfile  profile  = EnvironmentProfile::Baseline();
        EnvironmentProfile  baseline = EnvironmentProfile::Baseline();
        VirtualTimeState    clock;

        // Raw observation log. Verbose on purpose; findings are promoted from
        // this, deduplicated, rather than emitted per event.
        std::vector<EnvironmentObservation> observations;

        // Many environment APIs answer by filling a caller-supplied structure
        // rather than by returning a value, so the provenance tracker has to be
        // told where the answer landed. A handler that writes an output buffer
        // records it here; the analyzer picks it up after the call returns.
        struct PendingOutput {
            uint64_t address = 0;
            uint64_t size = 0;
            bool     valid() const { return address != 0 && size != 0; }
        } pendingOutput;

        void NoteOutputBuffer(uint64_t address, uint64_t size) {
            pendingOutput.address = address;
            pendingOutput.size = size;
        }
        void ClearOutputBuffer() { pendingOutput = PendingOutput{}; }

        void ApplyProfile(const EnvironmentProfile& p) {
            profile = p;
            clock.SetPolicy(p.timing);
            observations.clear();
        }

        // Record one answered environment query. Repeated queries of the same
        // property from the same address are counted, not duplicated.
        // Returns the index of the observation record.
        uint32_t Observe(const std::string& source, const std::string& property,
                         uint64_t address, uint64_t rva, uint64_t inputValue,
                         const std::string& supplied, const std::string& baselineValue);

        static constexpr size_t kMaxObservations = 4096;
    };

} // namespace Dracula
