#include "core/branch_influence.h"
#include <algorithm>

namespace Dracula {

    const char* EnvironmentOriginToString(EnvironmentOrigin origin) {
        switch (origin) {
            case EnvironmentOrigin::None:            return "None";
            case EnvironmentOrigin::Cpuid:           return "CPUID";
            case EnvironmentOrigin::Timestamp:       return "RDTSC";
            case EnvironmentOrigin::DescriptorTable: return "Descriptor table";
            case EnvironmentOrigin::PebField:        return "PEB";
            case EnvironmentOrigin::EnvironmentApi:  return "Environment API";
        }
        return "Unknown";
    }

    void BranchInfluenceTracker::MarkMemory(uint64_t start, uint64_t size, const OriginMark& mark) {
        if (!mark.Valid() || size == 0 || size > 0x10000) return;

        // An overlapping region is replaced rather than layered, so a second
        // call writing the same structure supersedes the first.
        for (auto& region : m_memory) {
            if (region.start == start) {
                region.size = size;
                region.mark = mark;
                return;
            }
        }
        if (m_memory.size() >= kMaxMarkedRegions) {
            m_memory.erase(m_memory.begin());   // bounded: drop the oldest
        }
        m_memory.push_back({start, size, mark});
    }

    OriginMark BranchInfluenceTracker::MemoryMark(uint64_t address) const {
        for (const auto& region : m_memory) {
            if (address >= region.start && address < region.start + region.size) {
                return region.mark;
            }
        }
        return OriginMark{};
    }

    void BranchInfluenceTracker::Reset() {
        m_registers.clear();
        m_spills.clear();
        m_memory.clear();
        m_flags = OriginMark{};
        m_flagsSetAt = 0;
        m_flagsSetRva = 0;
        m_flagsSetText.clear();
        m_branches.clear();
    }

    void BranchInfluenceTracker::MarkRegister(unsigned reg, const OriginMark& mark) {
        if (!mark.Valid()) return;
        m_registers[reg] = mark;
    }

    void BranchInfluenceTracker::ClearRegister(unsigned reg) {
        m_registers.erase(reg);
    }

    void BranchInfluenceTracker::ClearFlags() {
        m_flags = OriginMark{};
    }

    OriginMark BranchInfluenceTracker::RegisterMark(unsigned reg) const {
        auto it = m_registers.find(reg);
        return it != m_registers.end() ? it->second : OriginMark{};
    }

    void BranchInfluenceTracker::Propagate(unsigned reg,
                                           const std::vector<unsigned>& readRegs,
                                           const std::vector<unsigned>& writtenRegs) {
        (void)reg;
        OnDataFlow(readRegs, writtenRegs);
    }

    void BranchInfluenceTracker::OnDataFlow(const std::vector<unsigned>& readRegs,
                                            const std::vector<unsigned>& writtenRegs) {
        if (writtenRegs.empty()) return;

        // The strongest mark among the sources wins. Nothing read carrying a
        // mark means the destinations are now clean: a write from an untainted
        // source genuinely destroys the environment value that was there.
        OriginMark inherited;
        for (unsigned r : readRegs) {
            auto it = m_registers.find(r);
            if (it != m_registers.end() && it->second.Valid()) {
                inherited = it->second;
                break;
            }
        }

        for (unsigned w : writtenRegs) {
            if (inherited.Valid()) {
                m_registers[w] = inherited;
            } else {
                m_registers.erase(w);
            }
        }
    }

    void BranchInfluenceTracker::OnFlagsWritten(const std::vector<unsigned>& readRegs,
                                                uint64_t address, uint64_t rva,
                                                const std::string& text) {
        OriginMark inherited;
        for (unsigned r : readRegs) {
            auto it = m_registers.find(r);
            if (it != m_registers.end() && it->second.Valid()) {
                inherited = it->second;
                break;
            }
        }
        m_flags = inherited;
        m_flagsSetAt = address;
        m_flagsSetRva = rva;
        m_flagsSetText = text;
    }

    void BranchInfluenceTracker::OnSpill(uint64_t address, unsigned sourceReg) {
        auto it = m_registers.find(sourceReg);
        if (it == m_registers.end() || !it->second.Valid()) {
            m_spills.erase(address);
            return;
        }
        if (m_spills.size() >= kMaxSpills && m_spills.find(address) == m_spills.end()) {
            return;   // bounded: stop tracking rather than grow without limit
        }
        m_spills[address] = it->second;
    }

    void BranchInfluenceTracker::OnReload(unsigned destReg, uint64_t address) {
        auto it = m_spills.find(address);
        if (it != m_spills.end() && it->second.Valid()) {
            m_registers[destReg] = it->second;
        } else {
            m_registers.erase(destReg);
        }
    }

    OriginMark BranchInfluenceTracker::OnConditionalBranch(
        uint64_t address, uint64_t rva, const std::string& mnemonic,
        uint64_t takenTarget, uint64_t fallthrough, bool taken) {

        auto it = m_branches.find(address);
        if (it == m_branches.end()) {
            if (m_branches.size() >= kMaxBranches) return m_flags;
            InfluencedBranch b;
            b.branchAddress = address;
            b.branchRva = rva;
            b.mnemonic = mnemonic;
            b.takenTarget = takenTarget;
            b.fallthrough = fallthrough;
            it = m_branches.emplace(address, b).first;
        }

        InfluencedBranch& branch = it->second;
        if (taken) branch.observedTaken++;
        else       branch.observedNotTaken++;

        // Only the first attribution is kept. A later unmarked execution of the
        // same branch does not erase evidence that it was once environment-
        // driven, but neither does a later marked one overwrite the original.
        if (!branch.origin.Valid() && m_flags.Valid()) {
            branch.origin = m_flags;
            branch.comparedAt = m_flagsSetAt;
            branch.comparedRva = m_flagsSetRva;
            branch.compareText = m_flagsSetText;
        }
        return m_flags;
    }

} // namespace Dracula
