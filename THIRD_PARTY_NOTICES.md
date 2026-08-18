# Third-Party Software Notices and Licenses

Dracula incorporates and links with several open-source libraries and platform components. This document provides attribution and notices for third-party software components included or utilized by Dracula.

---

### 1. Capstone Engine
* **Project**: Capstone Disassembly Engine
* **Website**: https://www.capstone-engine.org/
* **License**: BSD 3-Clause "New" or "Revised" License
* **Copyright**: (c) 2013, Nguyen Anh Quynh <aquynh@gmail.com>

```text
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.
```

---

### 2. Unicorn Engine
* **Project**: Unicorn CPU Emulator Framework
* **Website**: https://www.unicorn-engine.org/
* **License**: GNU General Public License v2.0 / LGPL v2.1
* **Copyright**: (c) 2015, Nguyen Anh Quynh <aquynh@gmail.com> & Unicorn Engine contributors

---

### 3. SQLite3
* **Project**: SQLite Database Engine
* **Website**: https://www.sqlite.org/
* **License**: Public Domain

```text
The author disclaims copyright to this source code. In place of a legal notice,
here is a blessing:
   May you do good and not evil.
   May you find forgiveness for yourself and forgive others.
   May you share freely, never taking more than you give.
```

---

### 4. Zstandard (zstd)
* **Project**: Zstandard Fast Real-Time Compression Algorithm
* **Website**: https://github.com/facebook/zstd
* **License**: BSD 3-Clause License
* **Copyright**: (c) Meta Platforms, Inc. and affiliates.

---

### 5. Microsoft Debug Engine & DbgHelp API
* **Components**: `DbgHelp.dll`, `DbgEng.dll`
* **Provider**: Microsoft Corporation (Windows SDK / Redistributable Debugging Tools)
* **Usage**: Dynamic linking via Windows system APIs for symbol resolution, memory reading, and minidump parsing.

---

### 6. Event Tracing for Windows (ETW)
* **Provider**: Microsoft Corporation
* **Usage**: Native kernel telemetry provider subscriptions for process, thread, memory, and network event monitoring.

---

### 7. PE-sieve Concepts & Signatures
* **Project**: PE-sieve
* **Website**: https://github.com/hasherezade/pe-sieve
* **License**: BSD 2-Clause License
* **Copyright**: (c) 2017-2024, hasherezade

---

### 8. YARA Rules & Syntax
* **Project**: YARA
* **Website**: https://virustotal.github.io/yara/
* **License**: BSD 3-Clause License
* **Copyright**: (c) 2007-2024, VirusTotal / Google Inc.
