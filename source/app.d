import core.sys.windows.windows;
import core.sys.windows.psapi;
import core.sys.windows.windows;
import core.thread.osthread;
import core.time;
import std.datetime;
import std.stdio;
import std.string;
import std.algorithm.searching;
import lizard.logging;
import lizard.memory;

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
