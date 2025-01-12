module lizard.logger;

import std.stdio;

package static class Logger
{
    static
    {
        package bool loudLogging = false;

        /** 
         * Warn about failed read
         */
        void warnRead(string message)
        {
            writefln("Read error: failed to read %s", message);
        }

        /** 
         * General error warning
         */
        void error(string message, bool throwIt = false)
        {
            writefln("Error: %s", message);
            if (throwIt)
            {
                throw new Exception(message);
            }
        }

        /** 
        * Print some debug info
        */
        void info(string message)
        {
            if (loudLogging)
            {
                writefln("\x1B[90mInfo: %s\x1B[0m", message);
            }
        }
    }
}
