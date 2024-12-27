### Lizard: Memory editing library

Much suited to gamehacking, though can be used for other things.

#### Example usage

This prints the players name in the game "Cube 2: Sauerbraten".

```d
import std.stdio;
import lizard.memory;

void main()
{
    auto pm = ProcessMemory.fromWindowTitle("Cube 2: Sauerbraten");
    if (pm !is null)
    {
        string playerName;
        pm.readChainMemory("sauerbraten.exe", 0x2A5730, [0x274], playerName);
        writeln("Current player: ", playerName);
    }
}
```
