import winim

proc editMemory[T](pid: int, address: uint64, value: T) =
  let hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,
    false,
    pid.DWORD
  )

  if (hProcess == 0):
    echo("The process with PID ", pid, "does not exist")

  WriteProcessMemory(
    hProcess,
    cast[LPVOID](address),
    unsafeAddr value,
    sizeof(T).SIZE_T,
    nil
  )

  CloseHandle(hProcess)

let gamePid: int = 10;
let healthAddr: uint64 = 10;

editMemory[int32](gamePid, healthAddr, 100)
