# DynamoRIO Dynamic Binary Instrumentation

## Overview
- **Component**: DynamoRIO (v10.x)
- **Role in Dracula**: Deep dynamic binary instrumentation (DBI) engine for comprehensive instruction-level traces, basic-block code coverage, and memory access observation.
- **License**: BSD 3-Clause License.
- **Status**: Evaluated behind optional adapter `DynamoRioBackend`. Dracula uses Unicorn 2 and QEMU as primary deterministic CPU tracing engines; DynamoRIO remains an optional external backend.
