import core.sys.windows.windows;
import core.sys.windows.psapi;
import std.datetime;
import std.stdio;
import std.string;
import core.sys.windows.windows;
import core.thread.osthread;
import core.time;
import std.algorithm.searching;
import lizard.logging;

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
            Logger.error("Window not found: " ~ windowTitle);
            return null;
        }

        DWORD pid;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == 0)
        {
            Logger.error("Failed to get process ID for window: " ~ windowTitle);
            return null;
        }

        return new ProcessMemory(pid);
    }

    bool readCString(ulong address, ref string result)
    {
        SIZE_T bytesRead;
        char[256] buffer;

        if (!ReadProcessMemory(
                processHandle,
                cast(LPCVOID) address,
                buffer.ptr,
                buffer.length,
                &bytesRead
            ))
        {
            return false;
        }

        foreach (i; 0 .. bytesRead)
        {
            if (buffer[i] == 0)
            {
                result = cast(string) buffer[0 .. i].dup;
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
                static if (is(T == string))
                {
                    if (!readCString(finalAddress, value))
                    {
                        Logger.warnRead("string at final address");
                    }
                }
                else
                {
                    if (!readMemory(finalAddress, value))
                    {
                        Logger.warnRead("bytes at final address");
                    }
                }
            }
            else
            {
                Logger.warnRead("intermediate pointer");
            }
        }
    }
}

void main()
{
    auto pm = ProcessMemory.fromWindowTitle("Cube 2: Sauerbraten");
    if (pm !is null)
    {
        while (true)
        {
            string valuer;
            pm.readChainMemory("sauerbraten.exe", 0x2A5730, [0x274], valuer);
            writeln("Current player: ", valuer);
            byte[10] isAimingAtEnemy;
            pm.readChainMemory("sauerbraten.exe", 0x26DD08, [0x8C], isAimingAtEnemy);
            writeln(isAimingAtEnemy);
            byte[4] isShooting;
            pm.readChainMemory("sauerbraten.exe", 0x2A5730, [0x1FC], isShooting);
            writeln(isShooting);

            Thread.sleep(1.seconds);
        }

    }
}
