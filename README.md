# ALIEN XBOX Genesis

Experimental Android ARM64 foundation for Xbox Series X|S research. Launching the activity calls a C++ interpreter over an embedded x86-64 machine-code fixture. It adds the integers 1 through 9 and reports the actual registers and retired instruction count. Expected output is EAX 45, ECX 0, 30 instructions including INT3. The native core also queries the Android Vulkan loader.

## Execution model

The interpreter implements MOV EAX/ECX, imm32, ADD EAX, ECX, DEC ECX, JNZ rel8 and INT3. It models the zero flag and a flat, read-only instruction region. Unsupported encodings, truncated instructions, out-of-range branch targets and the instruction budget each produce distinct stop reasons. INT3 returns control to the diagnostic harness. Guest programs cannot call the host.

There is no Xbox package loader, general guest virtual memory, JIT, kernel or graphics command translation, audio, or input subsystem. Commercial games cannot boot. The Vulkan probe reports loader information only.

## Build and test

Use JDK 17, Gradle 8.11.1, SDK 35, NDK 27.2.12479018 and CMake 3.22.1. From the root run:

    gradle :app:assembleDebug

The push and manual GitHub Actions workflow runs the host tests, builds the ARM64 debug APK, checks its signature, alignment and native ELF machine, and uploads it as alien-xbox-genesis-arm64-debug.

Run native tests on a C++20 host:

    g++ -std=c++20 -Iapp/src/main/cpp app/src/main/cpp/guest.cpp tests/guest_test.cpp -o /tmp/guest-test
    /tmp/guest-test

## Upstream research

| Project | Relevant component | Integration scope |
| --- | --- | --- |
| [FEX](https://github.com/FEX-Emu/FEX/tree/main/FEXCore) | User-mode x86-64 to AArch64 translator | Candidate for CPU execution. First compare register and stop state on a shared fixture. The host must provide guest memory and exception handling. |
| [WinDurango](https://github.com/WinDurango/WinDurango) | KernelX, WinRT and D3D11.X interfaces for Xbox One ERA titles | Reference for tracing imports. Windows/UWP dependencies and Series compatibility need independent investigation. |
| [hakuX](https://github.com/rfandango/hakuX) | Android integration of a FEX fork, Vulkan, Adreno and AAudio | Reference for native Android integration. Its NV2A and original Xbox kernel target a different console. |
| [Xeo](https://github.com/chuckstation/xeo) | Android Gradle frontend and pinned Xenia upstream | Packaging and lifecycle reference. Archived Xbox 360 project. |

All guest execution code in this version is local. No upstream engine is linked.

## Genesis 0.2 homebrew loader

Choose a door to play Alien Doors. Android supplies a choice in ECX and a hidden door in EDX. The bundled AMD64 program computes the match and returns its verdict in EAX at INT3. Open homebrew executable sends a selected document through the same parser and interpreter, starting with both inputs zero. The viewport displays the stop reason, next or faulting RIP as a section-relative image RVA, accumulator and instruction count.

The loader accepts up to 4 MiB, AMD64 PE32+ images with a single executable section, an entry point inside initialized code and empty data directories. The CPU adds XOR EAX,EAX, CMP ECX,EDX, JZ and JMP short to the original subset. Each launch permits 100,000 instructions. Xbox retail packages, imported services, stack/data accesses, guest 3D and commercial titles remain unsupported.

The demo is assembled from samples/doors.s using the NDK LLVM bin directory on PATH:

    clang --target=x86_64-pc-windows-msvc -c samples/doors.s -o doors.obj
    lld-link /entry:entry /subsystem:console /nodefaultlib /fixed /timestamp:0 /out:app/src/main/assets/doors.exe doors.obj

## Alien Teal Ultimate 0.3.0

The landscape dashboard is bundled HTML/CSS in a local-only Android WebView. File selection, artwork decoding, CPU execution, device probes, input and report export run through the Android activity. The application requests no network or broad storage permission. Homebrew is validated and copied to private storage, and the legacy last-selected document is migrated when still readable.

Alien Doors, imported PE32+ details, favorites, library views, themes and input mapping are available from the navigation rail. Performance shows host memory, process CPU sampled across cores, Android thermal status and measured execution duration. Graphics enumerates actual Vulkan devices. Guest graphics, Xbox system services and retail game loading remain unavailable.

The workflow builds the ARM64 APK and checks ELF and ZIP alignment. A separate Android emulator job exercises the same source as x86_64, selects files through DocumentsUI and captures screenshots. The delivered APK is ARM64 only.
