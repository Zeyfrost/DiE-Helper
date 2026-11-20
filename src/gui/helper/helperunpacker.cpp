// DiE Helper (fork addition): static unpacking through DiE's own XStaticUnpacker classes
// (UPX, ASPack, FSG, MEW, NsPack, Petite, yC) and repair of renamed/scrambled UPX headers. Never executes anything.
#include "helperunpacker.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <cstring>

#include "xarchives.h"
#include "xformats.h"
#include "xpe.h"

static const XBinary::FT g_listUnpackerTypes[] = {XBinary::FT_PE32_UPX,    XBinary::FT_PE64_UPX,    XBinary::FT_PE32_ASPACK, XBinary::FT_PE32_FSG,
                                                  XBinary::FT_PE32_MEW,    XBinary::FT_PE32_NSPACK, XBinary::FT_PE32_PETITE, XBinary::FT_PE32_YODA};

QString HelperUnpacker::_packerName(XBinary::FT fileType)
{
    switch (fileType) {
        case XBinary::FT_PE32_UPX:
        case XBinary::FT_PE64_UPX: return QString("UPX");
        case XBinary::FT_PE32_ASPACK: return QString("ASPack");
        case XBinary::FT_PE32_FSG: return QString("FSG");
        case XBinary::FT_PE32_MEW: return QString("MEW");
        case XBinary::FT_PE32_NSPACK: return QString("NsPack");
        case XBinary::FT_PE32_PETITE: return QString("Petite");
        case XBinary::FT_PE32_YODA: return QString("yC (yoda's Crypter)");
        default: return XBinary::fileTypeIdToString(fileType);
    }
}

HelperUnpacker::INFO HelperUnpacker::detect(const QString &sFileName)
{
    INFO result = {};
    result.fileType = XBinary::FT_UNKNOWN;

    QFile file(sFileName);

    if (!file.open(QIODevice::ReadOnly)) {
        return result;
    }

    QSet<XBinary::FT> stTypes = XFormats::getFileTypes(&file, XBinary::FT_FLAG_EXECUTABLES | XBinary::FT_FLAG_STATICUNPACKERS);

    for (XBinary::FT fileType : g_listUnpackerTypes) {
        if (stTypes.contains(fileType)) {
            result.bAvailable = true;
            result.fileType = fileType;
            result.sPacker = _packerName(fileType);
            break;
        }
    }

    if (!result.bAvailable) {
        // UPX whose section names / magic were tampered with: virtual-only first section + RWX EP section +
        // the classic UPX entry stubs. DiE's stock signature usually still says "UPX (modified)".
        XPE pe(&file);

        if (pe.isValid() && !pe.isNETPresent()) {
            QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();

            if (listSections.count() >= 2 && listSections.at(0).SizeOfRawData == 0 && listSections.at(0).Misc.VirtualSize > 0) {
                // stock UPX stubs: x86 EXE, x64 EXE, x86 DLL, x64 DLL prologues (same as db/PE/packer_UPX.2.sg)
                bool bStub = pe.compareEntryPoint("60BE........8DBE") || pe.compareEntryPoint("53565755488D35") || pe.compareEntryPoint("807C2408") ||
                             pe.compareEntryPoint("48894C2408");
                result.bLooksLikeBrokenUpx = bStub;
            }
        }
    }

    file.close();

    return result;
}

HelperUnpacker::RESULT HelperUnpacker::_unpackAs(XBinary::FT fileType, const QString &sInput, const QString &sOutput, XBinary::PDSTRUCT *pPdStruct)
{
    RESULT result = {};

    QFile fileIn(sInput);

    if (!fileIn.open(QIODevice::ReadOnly)) {
        result.sError = QString("Cannot open %1").arg(sInput);
        return result;
    }

    QFile fileOut(sOutput);

    if (!fileOut.open(QIODevice::ReadWrite | QIODevice::Truncate)) {
        result.sError = QString("Cannot create %1").arg(sOutput);
        return result;
    }

    XBinary *pUnpacker = XFormats::createClass(fileType, &fileIn);

    if (!pUnpacker) {
        result.sError = QString("No static unpacker available for %1 in this build").arg(_packerName(fileType));
        return result;
    }

    result.listLog.append(QString("Static unpacker: %1 (%2), recognised: %3").arg(_packerName(fileType), XBinary::fileTypeIdToString(fileType), pUnpacker->isValid(pPdStruct) ? "yes" : "no"));

    // 1) XUPX implements unpack(); 2) the other classes go through the generic single-stream archive API
    bool bOK = pUnpacker->unpack(&fileOut, pPdStruct);
    result.listLog.append(QString("unpack(): %1").arg(bOK ? "ok" : "failed"));

    if (!bOK) {
        fileOut.resize(0);
        fileOut.seek(0);
        bOK = pUnpacker->unpackSingleStream(&fileOut, pUnpacker->getDefaultUnpackProperties(), pPdStruct);
        result.listLog.append(QString("unpackSingleStream(): %1").arg(bOK ? "ok" : "failed"));
    }

    delete pUnpacker;

    qint64 nOutSize = fileOut.size();
    fileOut.close();
    fileIn.close();

    if (!bOK || (nOutSize == 0)) {
        // 3) exactly what DiE's own "Unpack" button does: XArchives::decompressToFolder into a temp folder
        QTemporaryDir tempDir;

        if (tempDir.isValid() && XArchives::decompressToFolder(sInput, tempDir.path(), QMap<XBinary::UNPACK_PROP, QVariant>(), pPdStruct)) {
            QFileInfoList listFiles = QDir(tempDir.path()).entryInfoList(QDir::Files, QDir::Size);
            result.listLog.append(QString("decompressToFolder(): %1 file(s)").arg(listFiles.count()));

            if (!listFiles.isEmpty()) {
                QFile::remove(sOutput);
                bOK = QFile::copy(listFiles.first().absoluteFilePath(), sOutput);
                nOutSize = QFileInfo(sOutput).size();
            }
        } else {
            result.listLog.append(QString("decompressToFolder(): failed"));
        }
    }

    if (bOK && (nOutSize > 0)) {
        result.bSuccess = true;
        result.listLog.append(QString("Unpacked %1 -> %2 (%3 bytes)").arg(sInput, sOutput).arg(nOutSize));
    } else {
        result.sError = QString("%1 unpacker could not unpack this file (unsupported version or modified stub)").arg(_packerName(fileType));
        QFile::remove(sOutput);
    }

    return result;
}

HelperUnpacker::RESULT HelperUnpacker::unpack(const QString &sInput, const QString &sOutput, XBinary::PDSTRUCT *pPdStruct)
{
    INFO info = detect(sInput);

    if (!info.bAvailable) {
        RESULT result = {};
        result.sError = info.bLooksLikeBrokenUpx ? QString("Looks like UPX with a tampered header: use \"Repair UPX header\"")
                                                 : QString("No built-in static unpacker recognises this file (supported: UPX, ASPack, FSG, MEW, NsPack, Petite, yC)");
        return result;
    }

    return _unpackAs(info.fileType, sInput, sOutput, pPdStruct);
}

HelperUnpacker::RESULT HelperUnpacker::repairUpx(const QString &sInput, const QString &sOutput, XBinary::PDSTRUCT *pPdStruct)
{
    RESULT result = {};

    QString sRepaired = sOutput + QString(".repaired.tmp");
    QFile::remove(sRepaired);

    if (!XBinary::copyFile(sInput, sRepaired)) {
        result.sError = QString("Cannot copy %1").arg(sInput);
        return result;
    }

    {
        QFile file(sRepaired);

        if (!file.open(QIODevice::ReadWrite)) {
            result.sError = QString("Cannot open the copy");
            return result;
        }

        XPE pe(&file);

        if (!pe.isValid()) {
            result.sError = QString("Not a valid PE file");
            return result;
        }

        QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
        qint32 nEntryPointSection = pe.getEntryPointSection();

        // 1) section names: UPX0 = empty virtual section, UPX1 = compressed data + stub (EP), UPX2 = imports/loader data
        //    (".rsrc" is kept: UPX leaves the resource section name alone)
        for (qint32 i = 0; i < listSections.count(); i++) {
            QString sOld = QString::fromLatin1((const char *)listSections.at(i).Name, strnlen((const char *)listSections.at(i).Name, 8));
            QString sNew;

            if (i == 0) {
                sNew = QString("UPX0");
            } else if (i == nEntryPointSection || (i == 1)) {
                sNew = QString("UPX1");
            } else if (sOld != QString(".rsrc")) {
                sNew = QString("UPX2");
            }

            if (!sNew.isEmpty() && (sNew != sOld)) {
                pe.setSection_NameAsString(i, sNew);
                result.listLog.append(QString("Section #%1: \"%2\" -> \"%3\"").arg(i).arg(sOld, sNew));
            }
        }

        // 2) "UPX!" magic of the pack header: "<version>\0UPX!" just before the stub data, in the first 4 KiB.
        //    A wiped magic leaves "<d>.<dd>\0" followed by 4 zero bytes.
        QByteArray baHead = pe.read_array(0, qMin<qint64>(0x1000, pe.getSize()));

        if (!baHead.contains("UPX!")) {
            bool bRestored = false;

            for (qint32 i = 0; (i + 9) <= baHead.size(); i++) {
                const char *p = baHead.constData() + i;

                if ((p[0] >= '0') && (p[0] <= '9') && (p[1] == '.') && (p[2] >= '0') && (p[2] <= '9') && (p[3] >= '0') && (p[3] <= '9') && (p[4] == 0) && (p[5] == 0) &&
                    (p[6] == 0) && (p[7] == 0) && (p[8] == 0)) {
                    pe.write_array(i + 5, QByteArray("UPX!"));
                    result.listLog.append(QString("Restored \"UPX!\" magic at offset 0x%1 (after version \"%2\")").arg(i + 5, 0, 16).arg(QString::fromLatin1(p, 4)));
                    bRestored = true;
                    break;
                }
            }

            if (!bRestored) {
                result.listLog.append(QString("\"UPX!\" magic is missing and its slot was not found; unpacking may fail"));
            }
        } else {
            result.listLog.append(QString("\"UPX!\" magic present"));
        }

        file.close();
    }

    RESULT resultUnpack = _unpackAs(XBinary::FT_PE32_UPX, sRepaired, sOutput, pPdStruct);

    if (!resultUnpack.bSuccess) {
        // XUPX picks PE32/PE64 itself from the file; try the 64-bit type explicitly as well
        resultUnpack = _unpackAs(XBinary::FT_PE64_UPX, sRepaired, sOutput, pPdStruct);
    }

    result.listLog.append(resultUnpack.listLog);

    if (resultUnpack.bSuccess) {
        result.bSuccess = true;
        QFile::remove(sRepaired);
    } else {
        // keep the repaired (still packed) copy as the result so `upx -d` can be tried on it
        QFile::remove(sOutput);
        QFile::rename(sRepaired, sOutput);
        result.bSuccess = true;
        result.listLog.append(QString("The built-in unpacker still failed (%1). Saved the REPAIRED, still packed copy: try `upx -d` on it.").arg(resultUnpack.sError));
    }

    return result;
}
