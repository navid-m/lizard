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
        ulong[4] towrite = [1, 101, 110, 100];
        ulong[4] tostop = [0, 101, 110, 100];

        while (true)
        {
            // string valuer;
            // pm.readChainMemory("sauerbraten.exe", 0x2A5730, [0x274], valuer);
            // // writeln("Current player: ", valuer);
            byte[10] isAimingAtEnemy;
            pm.readChainMemory("sauerbraten.exe", 0x26DD08, [0x83C], isAimingAtEnemy);
            if (isAimingAtEnemy[0] != -54)
            {
                pm.writeChainMemory("sauerbraten.exe", 0x2A5730, [0x1FC], towrite);
            }
            else
            {
                pm.writeChainMemory("sauerbraten.exe", 0x2A5730, [0x1FC], tostop);
            }
            byte[4] isShooting;
            pm.readChainMemory("sauerbraten.exe", 0x2A5730, [0x1FC], isShooting);
            Thread.sleep(1.msecs);
        }

    }
}
