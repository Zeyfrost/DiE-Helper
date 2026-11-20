// DiE Helper (fork addition): Helper settings, kept in <exe dir>/helper.ini so DiE's own die.ini is never touched.
#include "helpersettings.h"

#include <QCoreApplication>
#include <QDir>
#include <QSettings>

#include "xoptions.h"

static const char *g_pszKeyHintsPath = "Helper/HintsPath";
static const char *g_pszKeyOutputFolder = "Helper/OutputFolder";
static const char *g_pszKeyCustomToolName = "Tools/CustomName";
static const char *g_pszKeyCustomToolArguments = "Tools/CustomArguments";

static QString _toolKey(HelperSettings::TOOL tool)
{
    switch (tool) {
        case HelperSettings::TOOL_UPX: return QString("Tools/Upx");
        case HelperSettings::TOOL_DE4DOT: return QString("Tools/De4dot");
        default: return QString("Tools/Custom");
    }
}

static QString _getValue(const char *pszKey)
{
    QSettings settings(HelperSettings::getSettingsFileName(), QSettings::IniFormat);

    return settings.value(pszKey).toString();
}

static void _setValue(const QString &sKey, const QString &sValue)
{
    QSettings settings(HelperSettings::getSettingsFileName(), QSettings::IniFormat);

    settings.setValue(sKey, sValue.trimmed());
}

QString HelperSettings::getSettingsFileName()
{
    return QCoreApplication::applicationDirPath() + QDir::separator() + "helper.ini";
}

QString HelperSettings::getDefaultHintsPath()
{
    return QString("$data/helper/hints.json");
}

QString HelperSettings::getHintsPath()
{
    return _getValue(g_pszKeyHintsPath);
}

void HelperSettings::setHintsPath(const QString &sPath)
{
    QString sValue = sPath.trimmed();

    if (sValue == getDefaultHintsPath()) {
        sValue.clear();
    }

    _setValue(g_pszKeyHintsPath, sValue);
}

QString HelperSettings::resolveHintsPath()
{
    QString sPath = getHintsPath();

    if (sPath.isEmpty()) {
        sPath = getDefaultHintsPath();
    }

    return XOptions::convertPathName(sPath);
}

QString HelperSettings::getOutputFolder()
{
    return _getValue(g_pszKeyOutputFolder);
}

void HelperSettings::setOutputFolder(const QString &sFolder)
{
    _setValue(g_pszKeyOutputFolder, sFolder);
}

QString HelperSettings::getToolPath(TOOL tool)
{
    QSettings settings(getSettingsFileName(), QSettings::IniFormat);

    return settings.value(_toolKey(tool)).toString();
}

void HelperSettings::setToolPath(TOOL tool, const QString &sPath)
{
    _setValue(_toolKey(tool), sPath);
}

QString HelperSettings::getCustomToolName()
{
    return _getValue(g_pszKeyCustomToolName);
}

void HelperSettings::setCustomToolName(const QString &sName)
{
    _setValue(g_pszKeyCustomToolName, sName);
}

QString HelperSettings::getCustomToolArguments()
{
    QString sResult = _getValue(g_pszKeyCustomToolArguments);

    return sResult.isEmpty() ? QString("\"%in%\" \"%out%\"") : sResult;
}

void HelperSettings::setCustomToolArguments(const QString &sArguments)
{
    _setValue(g_pszKeyCustomToolArguments, sArguments);
}
