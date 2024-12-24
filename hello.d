import core.sys.windows.windows;
import core.sys.windows.psapi;
import std.stdio;
import std.string;
import core.sys.windows.windows;
import std.algorithm.searching;

/** 
 * Handles process memory operations.
 */
class ProcessMemory
{
    HANDLE processHandle;
    DWORD processId;

    this(DWORD pid)
    {
        processId = pid;
        processHandle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            FALSE,
            processId
        );

        if (processHandle is null)
        {
            writeln("Failed to open process with PID: ", pid);
        }
    }

    ~this()
    {
        if (processHandle !is null)
        {
            CloseHandle(processHandle);
        }
    }

    /**
     * Reads memory from the specified address.
     *
     * Params:
     *   address = The memory address to read from.
     *   value = The variable to store the read value.
     *
     * Returns:
     *   True if the read was successful, false otherwise.
     */
    bool readMemory(T)(ulong address, ref T value)
    {
        if (processHandle is null)
            return false;

        SIZE_T bytesRead;
        auto result = ReadProcessMemory(
            processHandle,
            cast(LPCVOID) address,
            &value,
            T.sizeof,
            &bytesRead
        );

        return result != 0 && bytesRead == T.sizeof;
    }

    /**
     * Writes memory to the specified address.
     *
     * Params:
     *   address = The memory address to write to.
     *   value = The value to write.
     *
     * Returns:
     *   True if the write was successful, false otherwise.
     */
    bool writeMemory(T)(ulong address, T value)
    {
        if (processHandle is null)
            return false;

        SIZE_T bytesWritten;
        auto result = WriteProcessMemory(
            processHandle,
            cast(LPVOID) address,
            &value,
            T.sizeof,
            &bytesWritten
        );
        return result != 0 && bytesWritten == T.sizeof;
    }

    /**
     * Gets the process ID and handle by window title.
     *
     * Params:
     *   windowTitle = The title of the window to find.
     *
     * Returns:
     *   A ProcessMemory instance if the process is found, null otherwise.
     */
    static ProcessMemory fromWindowTitle(string windowTitle)
    {
        HWND hwnd = FindWindowA(null, toStringz(windowTitle));

        if (hwnd is null)
        {
            writeln("Window not found: ", windowTitle);
            return null;
        }

        DWORD pid;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == 0)
        {
            writeln("Failed to get process ID for window: ", windowTitle);
            return null;
        }

        return new ProcessMemory(pid);
    }

    bool readCString(ulong address, ref string result)
    {
        SIZE_T bytesRead;
        wchar[2000] wideBuffer;
        if (ReadProcessMemory(
                processHandle,
                cast(LPCVOID) address,
                wideBuffer.ptr,
                wideBuffer.length * wchar.sizeof,
                &bytesRead)
            )
        {
            auto end = wideBuffer[0 .. bytesRead / wchar.sizeof].countUntil(0);
            if (end >= 0)
            {
                result = cast(string) wideBuffer[0 .. end].idup;
                return true;
            }
        }
        return false;
    }

    ulong resolveAddress(string moduleName, ulong offset)
    {
        DWORD needed;
        HMODULE[] modules = new HMODULE[1024];
        if (
            EnumProcessModules(
                cast(HANDLE) processHandle,
                cast(HMODULE*) modules.ptr,
                cast(DWORD)(modules.length * HMODULE.sizeof),
                cast(LPDWORD)&needed
            )
            )
        {
            foreach (mod; modules[0 .. needed / HMODULE.sizeof])
            {
                char[256] moduleNameBuffer;
                if (GetModuleBaseNameA(
                        cast(HANDLE) processHandle,
                        mod,
                        moduleNameBuffer.ptr,
                        moduleNameBuffer.length)
                    )
                {
                    auto foundModuleName = moduleNameBuffer[0 .. moduleNameBuffer.indexOf(0)];
                    if (foundModuleName == moduleName)
                    {
                        return cast(ulong) mod + offset;
                    }
                }

            }
        }
        return 0;
    }

    void readChainMemory(T)(string exeName, ulong address, ulong[] offsets, ref T value)
    {
        foreach (offset; offsets)
        {
            ulong intermediate;
            if (readMemory(resolveAddress(exeName, address), intermediate))
            {
                ulong finalAddress = intermediate + offset;
                string val;
                if (readCString(finalAddress, val))
                {
                    value = val;
                }
                else
                {
                    writeln("Failed to read memory at final address.");
                }
            }
            else
            {
                writeln("Failed to read intermediate pointer.");
            }
        }
    }
}

void main()
{
    auto pm = ProcessMemory.fromWindowTitle("Cube 2: Sauerbraten");
    if (pm !is null)
    {
        string valuer;
        pm.readChainMemory("sauerbraten.exe", 0x2A5730, [0x274], valuer);
        writeln(valuer);
    }
}
