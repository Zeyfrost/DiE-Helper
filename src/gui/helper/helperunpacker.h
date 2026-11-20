// DiE Helper (fork addition): static unpacking through DiE's own XStaticUnpacker classes
// (UPX, ASPack, FSG, MEW, NsPack, Petite, yC) and repair of renamed/scrambled UPX headers. Never executes anything.
#ifndef HELPERUNPACKER_H
#define HELPERUNPACKER_H

#include <QStringList>

#include "xbinary.h"

class HelperUnpacker {
public:
    struct INFO {
        bool bAvailable;          // a built-in static unpacker recognises the file
        XBinary::FT fileType;     // e.g. FT_PE32_UPX
        QString sPacker;          // "UPX", "ASPack", ...
        bool bLooksLikeBrokenUpx; // UPX layout/stub but renamed sections or wiped magic: "Repair UPX header" applies
    };

    struct RESULT {
        bool bSuccess;
        QString sError;
        QStringList listLog;
    };

    static INFO detect(const QString &sFileName);
    // Writes the unpacked file to sOutput (sInput is only read)
    static RESULT unpack(const QString &sInput, const QString &sOutput, XBinary::PDSTRUCT *pPdStruct = nullptr);
    // Restores UPX0/UPX1/UPX2 section names and the "UPX!" magic in a copy, then unpacks it into sOutput.
    // If unpacking still fails, sOutput holds the repaired (still packed) copy, so `upx -d` can be tried on it.
    static RESULT repairUpx(const QString &sInput, const QString &sOutput, XBinary::PDSTRUCT *pPdStruct = nullptr);

private:
    static RESULT _unpackAs(XBinary::FT fileType, const QString &sInput, const QString &sOutput, XBinary::PDSTRUCT *pPdStruct);
    static QString _packerName(XBinary::FT fileType);
};

#endif  // HELPERUNPACKER_H
