module lizard.logging;

import std.stdio;

package class Logger
{
    static
    {
        private string acerrMsg = "failed to read";

        /** 
         * Warn about failed read
         */
        void warnRead(string message)
        {
            writefln("Read error: %s %s", acerrMsg, message);
        }

        void error(string message)
        {
            writefln("Error: %s", message);
        }
    }
}
