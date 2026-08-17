#pragma once

//
// Bounded environment provenance for emulated execution.
//
// The single most important question the Anti-Evasion engine asks is not "did
// this sample read an environment property" but "did the value it read decide
// where execution went". A program that calls GetSystemInfo and prints the
// result is not evading anything; a program that calls it and exits when the
// processor count is under four is.
//
// This is deliberately NOT a full dynamic taint engine. It tracks one thing,
// at register granularity, within a single emulated run:
//
//      environment-producing operation   (CPUID / RDTSC / environment API)
//            ↓ writes
//      general purpose register
//            ↓ moves, arithmetic
//      other registers
//            ↓ CMP / TEST / SUB
//      flags
//            ↓
//      conditional branch                → attributed to the origin
//
// Anything it cannot follow (memory round trips beyond a small spill map, SIMD,
// indirect control flow) simply drops the mark. It under-reports rather than
// guessing, because an over-eager attribution would inflate confidence, which
// is the one thing this engine must never do.
//

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>

namespace Dracula {

    // What produced an environment value.
    enum class EnvironmentOrigin {
        None,
        Cpuid,
        Timestamp,        // RDTSC / RDTSCP
        DescriptorTable,  // SIDT / SGDT / SLDT / STR / SMSW
        PebField,         // direct PEB read (BeingDebugged, NtGlobalFlag)
        EnvironmentApi    // an HLE environment-information API return value
    };

    const char* EnvironmentOriginToString(EnvironmentOrigin origin);

    struct OriginMark {
        EnvironmentOrigin origin = EnvironmentOrigin::None;
        uint64_t          producedAt = 0;    // address of the producing insn
        uint64_t          producedRva = 0;
        std::string       property;          // "Hypervisor presence", "TSC"
        uint32_t          observationId = 0; // index into the run's observations

        bool Valid() const { return origin != EnvironmentOrigin::None; }
    };

    // A conditional branch whose decision was attributed to an environment value.
    struct InfluencedBranch {
        uint64_t    branchAddress = 0;
        uint64_t    branchRva = 0;
        std::string mnemonic;
        OriginMark  origin;
        uint64_t    comparedAt = 0;      // address of the CMP/TEST that set flags
        uint64_t    comparedRva = 0;
        std::string compareText;         // "test ecx, ecx" style
        uint32_t    observedTaken = 0;
        uint32_t    observedNotTaken = 0;
        uint64_t    takenTarget = 0;
        uint64_t    fallthrough = 0;
    };

    // Register-granular provenance for one emulated run.
    //
    // Registers are identified by Capstone's canonical 64-bit register id so
    // that EAX/AX/AL all resolve to the same slot.
    class BranchInfluenceTracker {
    public:
        void Reset();

        // Mark a register (canonical id) as carrying an environment value.
        void MarkRegister(unsigned reg, const OriginMark& mark);

        // Propagate through one instruction. `readRegs` / `writtenRegs` come
        // from Capstone register access analysis; `writesFlags` and `readsFlags`
        // describe EFLAGS involvement.
        void Propagate(unsigned reg, const std::vector<unsigned>& readRegs,
                       const std::vector<unsigned>& writtenRegs);

        // A compare/test instruction: flags inherit the marks of what it read.
        void OnFlagsWritten(const std::vector<unsigned>& readRegs,
                            uint64_t address, uint64_t rva,
                            const std::string& text);

        // Data movement / arithmetic: written registers inherit read marks.
        void OnDataFlow(const std::vector<unsigned>& readRegs,
                        const std::vector<unsigned>& writtenRegs);

        // Stack spill/reload of a marked value, bounded to a small map.
        void OnSpill(uint64_t address, unsigned sourceReg);
        void OnReload(unsigned destReg, uint64_t address);

        // Many environment APIs answer by filling a caller-supplied structure.
        // The written region is marked so that a later load out of it carries
        // the provenance into a register. Bounded to a small number of regions.
        void MarkMemory(uint64_t start, uint64_t size, const OriginMark& mark);
        OriginMark MemoryMark(uint64_t address) const;

        // A conditional branch executed. Returns the attributed origin, if any.
        OriginMark OnConditionalBranch(uint64_t address, uint64_t rva,
                                       const std::string& mnemonic,
                                       uint64_t takenTarget, uint64_t fallthrough,
                                       bool taken);

        void ClearRegister(unsigned reg);
        void ClearFlags();

        OriginMark RegisterMark(unsigned reg) const;
        bool FlagsMarked() const { return m_flags.Valid(); }

        const std::map<uint64_t, InfluencedBranch>& InfluencedBranches() const {
            return m_branches;
        }

    private:
        std::map<unsigned, OriginMark> m_registers;
        std::map<uint64_t, OriginMark> m_spills;   // bounded stack slots

        struct MarkedRegion {
            uint64_t   start = 0;
            uint64_t   size = 0;
            OriginMark mark;
        };
        std::vector<MarkedRegion> m_memory;        // bounded output buffers
        OriginMark                     m_flags;
        uint64_t                       m_flagsSetAt = 0;
        uint64_t                       m_flagsSetRva = 0;
        std::string                    m_flagsSetText;

        std::map<uint64_t, InfluencedBranch> m_branches;

        static constexpr size_t kMaxSpills = 64;
        static constexpr size_t kMaxBranches = 512;
        static constexpr size_t kMaxMarkedRegions = 32;
    };

} // namespace Dracula
