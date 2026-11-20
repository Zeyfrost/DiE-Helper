// DiE Helper (fork addition): static .NET metadata review: obfuscated names with readable aliases, protector markers, high-entropy IL bodies, user strings.
// STATUS: done (written, not compiled yet)
// Reads the metadata as data only; the assembly is never loaded, JIT-compiled or executed. No GUI code; safe on a worker thread.
#ifndef HELPERNETINFO_H
#define HELPERNETINFO_H

#include <QList>
#include <QString>
#include <QStringList>

#include "xbinary.h"

class HelperNetInfo {
public:
    struct NAME {
        QString sKind;      // "Type", "Method", "Field", "Property", "Event"
        QString sOriginal;  // as stored in #Strings, non-printable characters escaped as \uXXXX (types: "Namespace.Name")
        QString sAlias;     // readable replacement for obfuscated names ("Class_0001", "method_0007", ...); empty for normal names
        bool bObfuscated;
    };

    struct MARKER {
        QString sName;      // "ConfuserEx", ".NET Reactor", "Module initializer", "Encrypted method bodies", ...
        QString sDetails;   // the concrete evidence (which metadata string / how many rows / which resource)
    };

    struct METHOD {
        QString sName;      // "Type::Method" (escaped)
        qint64 nOffset;     // file offset of the IL code (after the method header)
        qint64 nSize;       // IL code size
        double dEntropy;
    };

    struct RESULT {
        bool bIsValid;      // false: not a PE / not .NET / metadata unreadable (see sError)
        QString sError;
        QList<NAME> listNames;              // compiler-generated names (<...>, .ctor, ...) are left out
        QList<MARKER> listMarkers;
        QList<METHOD> listTopEntropyMethods;  // up to 20, entropy descending, IL code of 64+ bytes only
        QStringList listUserStrings;        // #US heap in heap order (capped)
    };

    static RESULT analyze(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct = nullptr);
};

#endif  // HELPERNETINFO_H
