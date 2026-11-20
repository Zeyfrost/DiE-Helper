// DiE Helper (fork addition): Helper settings, kept in <exe dir>/helper.ini so DiE's own die.ini is never touched.
#ifndef HELPERSETTINGS_H
#define HELPERSETTINGS_H

#include <QString>

class HelperSettings {
public:
    enum TOOL {
        TOOL_UPX = 0,   // upx.exe        (static unpack: upx -d)
        TOOL_DE4DOT,    // de4dot.exe     (.NET deobfuscation / renaming)
        TOOL_CUSTOM,    // any other tool (command line template)
        __TOOL_SIZE
    };

    static QString getSettingsFileName();

    static QString getDefaultHintsPath();   // "$data/helper/hints.json"
    static QString getHintsPath();          // as stored; empty means default
    static void setHintsPath(const QString &sPath);
    static QString resolveHintsPath();      // stored or default, with $data expanded

    // Where actions write their results: empty = ask with a Save-as dialog every time (default)
    static QString getOutputFolder();
    static void setOutputFolder(const QString &sFolder);

    // External tools (optional): executable path; empty = not configured, the button is hidden
    static QString getToolPath(TOOL tool);
    static void setToolPath(TOOL tool, const QString &sPath);
    // TOOL_CUSTOM only: display name and argument template (%in% = input copy, %out% = output file)
    static QString getCustomToolName();
    static void setCustomToolName(const QString &sName);
    static QString getCustomToolArguments();
    static void setCustomToolArguments(const QString &sArguments);
};

#endif  // HELPERSETTINGS_H
