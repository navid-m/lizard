module lizard.configuration;

import lizard.logger;

/** 
 * Toggle showing extended information in the console.
 */
public void setLoudLogging(bool loud)
{
    Logger.loudLogging = loud;
}
