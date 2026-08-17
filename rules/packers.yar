/*
    Packer, Protector, and Obfuscator Signatures
*/

rule UPX_Packer {
    meta:
        description = "Detects UPX compressed executable"
        author = "SandboxEngine"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX2"
        $upx_sig = "$Info: This file is packed with the UPX"
    condition:
        uint16(0) == 0x5A4D and (2 of ($upx*))
}

rule Themida_WinLicense {
    meta:
        description = "Detects Themida or WinLicense protector"
        author = "SandboxEngine"
    strings:
        $themida1 = ".themida" nocase
        $themida2 = "Themida" nocase
        $winlicense = "WinLicense" nocase
        $oreans = "Oreans Technologies" nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule VMProtect {
    meta:
        description = "Detects VMProtect virtualized binary"
        author = "SandboxEngine"
    strings:
        $vmp0 = ".vmp0" nocase
        $vmp1 = ".vmp1" nocase
        $vmp2 = ".vmp2" nocase
        $vmprotect = "VMProtect" nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule ASPack {
    meta:
        description = "Detects ASPack packer"
        author = "SandboxEngine"
    strings:
        $aspack1 = ".aspack" nocase
        $aspack2 = "ASPack" nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PECompact {
    meta:
        description = "Detects PECompact packer"
        author = "SandboxEngine"
    strings:
        $pec1 = "PECompact2" nocase
        $pec2 = "PEC2"
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule MPRESS {
    meta:
        description = "Detects MPRESS compressed binary"
        author = "SandboxEngine"
    strings:
        $mpress1 = ".MPRESS1" nocase
        $mpress2 = ".MPRESS2" nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule EnigmaProtector {
    meta:
        description = "Detects Enigma Protector"
        author = "SandboxEngine"
    strings:
        $enigma1 = ".enigma1" nocase
        $enigma2 = ".enigma2" nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}
