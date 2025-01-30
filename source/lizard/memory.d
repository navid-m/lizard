module lizard.memory;

import core.sys.windows.windows;
import core.sys.windows.psapi;
import core.sys.windows.windows;
import core.sys.windows.tlhelp32;
import core.sync.mutex;
import core.stdc.string;
import core.stdc.stdlib;
import core.thread.osthread;
import core.time;
import std.datetime;
import std.stdio;
import std.conv;
import std.string;
import std.algorithm.searching;
import std.digest;
import std.variant;
import lizard.logger;

/** 
 * Single memory location bound to one fixed value.
 */
package struct FrozenValue
{
    ulong address;
    Variant value;
    Thread thread;
    bool active;
}

/** 
 * Handles process memory operations.
 */
public class ProcessMemory
{
    private Mutex freezeMutex;
    private FrozenValue[string] frozenValues;

    HANDLE processHandle;
    DWORD processId;
    BOOL isWow64;
    BOOL isSelfWow64;

    this(DWORD pid)
    {
        IsWow64Process(GetCurrentProcess(), &isSelfWow64);

        processId = pid;
        processHandle = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            FALSE,
            processId
        );

        if (processHandle !is null)
        {
            IsWow64Process(processHandle, &isWow64);
            if (isWow64 != isSelfWow64)
            {
                Logger.error(
                    "Architecture mismatch: The target and current process must be same architecture (x86 or x64)."
                );
                CloseHandle(processHandle);
                processHandle = null;
                exit(1);
            }
            freezeMutex = new Mutex();
        }
        else
        {
            Logger.error("Failed to open process with PID: " ~ to!string(pid));
        }
    }

    ~this()
    {
        synchronized (freezeMutex)
        {
            foreach (ref frozenValue; frozenValues)
            {
                frozenValue.active = false;
                frozenValue.thread.join();
            }
        }
        if (processHandle !is null)
        {
            CloseHandle(processHandle);
        }
    }

    /**
    * Read memory from the specified address.
    *
    * Params:
    *   address = The memory address to read from.
    *   value = The variable to store the read value.
    *
    * Returns:
    *   True if the read was successful, false otherwise.
    */
    public bool readMemory(T)(ulong address, ref T value)
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
    * Freeze a memory value at a specific address.
    *
    * Params:
    *   address = The memory address to freeze
    *   value = The value to maintain at that address
    *   identifier = Unique string to identify this frozen value
    *
    * Returns:
    *   True if freezing was initiated successfully
    */
    public bool freezeValue(T)(ulong address, T value, string identifier)
    {
        synchronized (freezeMutex)
        {
            if (identifier in frozenValues)
            {
                Logger.error("Value with identifier '" ~ identifier ~ "' is already frozen");
                return false;
            }

            auto frozenValue = FrozenValue(address, Variant(value), null, true);
            frozenValue.thread = new Thread({
                while (frozenValue.active)
                {
                    if (!writeMemory(address, value))
                    {
                        Logger.info(
                            "Could not maintain frozen value at address: " ~ to!string(address)
                        );
                    }
                    Thread.sleep(dur!"msecs"(20));
                }
            });

            frozenValues[identifier] = frozenValue;
            frozenValue.thread.start();
            Logger.info("Started freezing value at address " ~ to!string(address));
            return true;
        }
    }

    /**
     * Unfreeze a previously frozen memory value.
     *
     * Params:
     *   identifier = The identifier of the value to unfreeze
     *
     * Returns:
     *   True if the value was successfully unfrozen
     */
    public bool unfreezeValue(T)(string identifier)
    {
        synchronized (freezeMutex)
        {
            if (identifier !in frozenValues)
            {
                Logger.error("No frozen value found with identifier: " ~ identifier);
                return false;
            }
            frozenValues[identifier].active = false;
            frozenValues[identifier].thread.join();
            frozenValues.remove(identifier);
            Logger.info("Stopped freezing value with identifier: " ~ identifier);
            return true;
        }
    }

    /**
     * Check if a value is currently frozen.
     *
     * Params:
     *   identifier = The identifier to check
     *
     * Returns:
     *   True if the value is currently frozen
     */
    public bool isValueFrozen(string identifier)
    {
        synchronized (freezeMutex)
        {
            return (identifier in frozenValues) !is null;
        }
    }

    /**
     * Read a C-style double from memory.
     *
     * Params:
     *   address = The memory address to read from.
     *   result = The variable to store the read value.
     *
     * Returns:
     *   True if the read was successful, false otherwise.
     */
    public bool readCDouble(ulong address, ref double result)
    {
        if (processHandle is null || address == 0)
        {
            Logger.error("Invalid process handle or address.");
            return false;
        }

        SIZE_T bytesRead;
        double tempResult;
        if (!ReadProcessMemory(
                processHandle,
                cast(LPCVOID) address,
                &tempResult,
                double.sizeof,
                &bytesRead
            ) || bytesRead != double.sizeof)
        {
            DWORD error = GetLastError();
            Logger.error("ReadProcessMemory failed with error code: " ~ to!string(error));
            return false;
        }

        result = tempResult;
        return true;
    }

    /***
    * Read a C-style float from memory.
    *
    * Params:
    *   address = The memory address to read from.
    *   result = The variable to store the read value.
    *
    * Returns:
    *   True if the read was successful, false otherwise.
    */
    public bool readCFloat(ulong address, ref float result)
    {
        if (processHandle is null || address == 0)
        {
            Logger.error("Invalid process handle or address.");
            return false;
        }

        SIZE_T bytesRead;
        float tempResult;
        if (!ReadProcessMemory(
                processHandle,
                cast(LPCVOID) address,
                &tempResult,
                float.sizeof,
                &bytesRead
            ) || bytesRead != float.sizeof)
        {
            DWORD error = GetLastError();
            Logger.error("ReadProcessMemory failed with error code: " ~ to!string(error));
            return false;
        }

        result = tempResult;
        return true;
    }

    /**
     * Write memory to the specified address.
     *
     * Params:
     *   address = The memory address to write to.
     *   value = The value to write.
     *
     * Returns:
     *   True if the write was successful, false otherwise.
     */
    public bool writeMemory(T)(ulong address, T value)
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
     * Write using VirtualProtectEx to temporarily modify page permissions.
     *
     * Params:
     *   address = Memory address to write to.
     *   value = The value to write.
     *
     * Returns: Whether the permission change and write was successful.
     */
    public bool writeMemoryProtected(T)(ulong address, T value)
    {
        if (processHandle is null)
            return false;

        DWORD oldProtect;
        DWORD previousPermissions;
        SIZE_T bytesWritten;

        if (
            !VirtualProtectEx(
                processHandle,
                cast(LPVOID)
                address,
                T.sizeof,
                PAGE_EXECUTE_READWRITE,
                &oldProtect
            )
            )
        {
            Logger.error("Failed to change page permissions to execute/read/write.");
            return false;
        }

        // Perform write
        auto result = WriteProcessMemory(
            processHandle,
            cast(LPVOID) address,
            &value,
            T.sizeof,
            &bytesWritten
        );

        // Restore original permissions
        VirtualProtectEx(
            processHandle,
            cast(LPVOID) address,
            T.sizeof,
            oldProtect,
            &previousPermissions
        );

        return result != 0 && bytesWritten == T.sizeof;
    }

    public void writeChainMemory(T)(string exeName, ulong address, ulong[] offsets, T value)
    {
        foreach (offset; offsets)
        {
            ulong intermediate;
            if (readMemory(resolveAddress(exeName, address), intermediate))
            {
                ulong finalAddress = intermediate + offset;
                if (!writeMemory(finalAddress, value))
                {
                    Logger.error("Failed to write value at final address");
                }
            }
            else
            {
                Logger.error("Failed to read intermediate pointer");
            }
        }
    }

    /**
     * Get the process ID and handle by window title.
     *
     * Params:
     *   windowTitle = The title of the window to find.
     *
     * Returns:
     *   A ProcessMemory instance if the process is found, null otherwise.
     */
    public static ProcessMemory fromWindowTitle(string windowTitle)
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

    /**
    * Get the process ID and handle by process name.
    *
    * Params:
    *   processName = The name of the process to find.
    *
    * Returns:
    *   A ProcessMemory instance if the process is found, null otherwise.
    */
    public static ProcessMemory fromProcessName(string processName)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (snapshot == INVALID_HANDLE_VALUE)
        {
            Logger.error("Failed to create snapshot of processes", true);
            return null;
        }

        try
        {
            PROCESSENTRY32 entry;
            entry.dwSize = PROCESSENTRY32.sizeof;
            if (Process32First(snapshot, &entry))
            {
                do
                {
                    string currentProcessName = to!string(
                        entry.szExeFile[0 .. entry.szExeFile.indexOf('\0')]
                    );
                    if (strip(currentProcessName) == strip(processName))
                    {
                        return new ProcessMemory(entry.th32ProcessID);
                    }
                }
                while (Process32Next(snapshot, &entry));
            }
        }
        finally
        {
            CloseHandle(snapshot);
        }

        Logger.error("Could not find process: " ~ processName, true);
        return null;
    }

    /** 
     * Read string in C format.
     *
     * Params:
     *   address = Memory address
     *   result = Result will be written to here
     *
     * Returns: Whether the read was successful or not.
     */
    public bool readCString(ulong address, ref string result)
    {
        if (address == 0)
        {
            Logger.error("Attempted to read from null address");
            return false;
        }

        SIZE_T bytesRead;
        char[256] buffer;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(
                processHandle,
                cast(LPCVOID) address,
                &mbi,
                MEMORY_BASIC_INFORMATION.sizeof
            ) == 0)
        {
            Logger.error("VirtualQueryEx failed for address: " ~ to!string(address));
            return false;
        }

        if (!(mbi.State & MEM_COMMIT))
        {
            Logger.error("Memory at address is not committed: " ~ to!string(address));
            return false;
        }

        if (!ReadProcessMemory(
                processHandle,
                cast(LPCVOID) address,
                buffer.ptr,
                buffer.length,
                &bytesRead
            ))
        {
            DWORD error = GetLastError();
            Logger.error("ReadProcessMemory call failed with error code: " ~ to!string(error));
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

    public ulong resolveAddress(string moduleName, ulong offset)
    {
        DWORD needed;
        HMODULE[] modules = new HMODULE[1024];

        Logger.info("Trying to resolve " ~ moduleName ~ " with offset " ~ to!string(offset));

        if (EnumProcessModules(
                cast(HANDLE) processHandle,
                cast(HMODULE*) modules.ptr,
                cast(DWORD)(modules.length * HMODULE.sizeof),
                cast(LPDWORD)&needed
            ))
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
                    Logger.info("Found module: " ~ to!string(foundModuleName));
                    if (foundModuleName == moduleName)
                    {
                        auto finalAddress = cast(ulong) mod + offset;
                        Logger.info("Found module, final address: " ~ to!string(finalAddress));
                        return finalAddress;
                    }
                }
            }
        }
        else
        {
            Logger.error("EnumProcessModules failed with error: " ~ to!string(GetLastError()));
        }
        return 0;
    }

    /**  
    * Only for use with long pointers.
    *
    * Do not use for simple offsets.
    *
    * Params:
    *   exeName = Module name or process executable
    *   address = Address offset for module name
    *   offsets = List of offsets
    *   value = Value to read into
    */
    public void readChainMemory(T)(string exeName, ulong address, ulong[] offsets, ref T value)
    {
        auto baseAddr = resolveAddress(exeName, address);
        Logger.info("Base address resolved to: " ~ to!string(baseAddr));

        if (baseAddr == 0)
        {
            Logger.error("Failed to resolve base address for " ~ exeName);
            return;
        }

        ulong currentAddress = baseAddr;
        ulong lastOffset;

        foreach (i, offset; offsets)
        {
            ulong intermediate;
            Logger.info("Reading address: " ~ to!string(currentAddress));

            if (readMemory(currentAddress, intermediate))
            {
                currentAddress = intermediate + offset;
                Logger.info(
                    "New address after offset "
                        ~ to!string(
                            offset
                        ) ~ ": " ~ to!string(
                            currentAddress
                        )
                );
            }
            else
            {
                Logger.error("Failed to read at address: " ~ to!string(currentAddress));
                return;
            }
            lastOffset = offset;
        }

        static if (is(T == string))
        {
            if (!readCString(currentAddress, value))
            {
                Logger.error(
                    "Failed to read string at final address: "
                        ~ to!string(
                            currentAddress
                        )
                );
            }
        }
        else static if (is(T == double))
        {
            if (!readCDouble(currentAddress, value))
            {
                Logger.error(
                    "Failed to read double at final address: "
                        ~ to!string(
                            currentAddress
                        )
                );
            }
        }
        else
        {
            if (!readMemory(currentAddress, value))
            {
                Logger.error(
                    "Failed to read value at final address: " ~
                        to!string(
                            currentAddress
                        ) ~ " (reached via final offset " ~
                        to!string(
                            lastOffset
                        ) ~ ")"
                );
            }
        }
    }

    /** 
    * Resolve address by pointer chain.
    * 
    * Params:
    *   exeName = Module name
    *   address = Base address
    *   offsets = Pointer offsets
    *
    * Returns: The resolved address
    */
    public ulong resolveChainAddress(string exeName, ulong address, ulong[] offsets)
    {
        auto baseAddr = resolveAddress(exeName, address);
        Logger.info("Base address resolved to: " ~ to!string(baseAddr));

        if (baseAddr == 0)
        {
            Logger.error("Failed to resolve base address for " ~ exeName);
        }

        ulong currentAddress = baseAddr;
        foreach (i, offset; offsets)
        {
            ulong intermediate;
            Logger.info("Reading address: " ~ to!string(currentAddress));

            if (readMemory(currentAddress, intermediate))
            {
                currentAddress = intermediate + offset;
                Logger.info(
                    "New address after offset "
                        ~ to!string(
                            offset
                        ) ~ ": " ~ to!string(
                            currentAddress
                        )
                );
            }
        }
        return currentAddress;
    }

    /** 
    * Patch some memory.
    */
    public void patchMemory(ubyte* dst, ubyte* src, uint size)
    {
        DWORD oldProtect;
        VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(dst, src, size);
        VirtualProtect(dst, size, oldProtect, &oldProtect);
    }
}
