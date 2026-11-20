// DiE Helper (fork addition): small PE edits, always applied to a NEW copy of the file.
#include "helperpesurgery.h"

#include <QFile>
#include <QSet>
#include <cstring>

#include "xpe.h"

static QString _sectionName(const XPE_DEF::IMAGE_SECTION_HEADER &header)
{
    return QString::fromLatin1((const char *)header.Name, (int)strnlen((const char *)header.Name, 8));
}

static QString _flags(quint32 nCharacteristics)
{
    return QString("%1%2%3")
        .arg((nCharacteristics & XPE_DEF::S_IMAGE_SCN_MEM_READ) ? "R" : "-", (nCharacteristics & XPE_DEF::S_IMAGE_SCN_MEM_WRITE) ? "W" : "-",
             (nCharacteristics & XPE_DEF::S_IMAGE_SCN_MEM_EXECUTE) ? "X" : "-");
}

bool HelperPeSurgery::_openCopy(const QString &sInput, const QString &sOutput, QFile *pFile, RESULT *pResult)
{
    if (QFile::exists(sOutput) && !QFile::remove(sOutput)) {
        pResult->sError = QString("Cannot overwrite %1").arg(sOutput);
        return false;
    }

    if (!XBinary::copyFile(sInput, sOutput)) {
        pResult->sError = QString("Cannot copy %1 to %2").arg(sInput, sOutput);
        return false;
    }

    pFile->setFileName(sOutput);

    if (!pFile->open(QIODevice::ReadWrite)) {
        pResult->sError = QString("Cannot open %1 for writing").arg(sOutput);
        return false;
    }

    XPE pe(pFile);

    if (!pe.isValid()) {
        pResult->sError = QString("Not a valid PE file");
        pFile->close();
        QFile::remove(sOutput);
        return false;
    }

    pResult->listLog.append(QString("Copy: %1").arg(sOutput));

    return true;
}

HelperPeSurgery::RESULT HelperPeSurgery::setEntryPoint(const QString &sInput, const QString &sOutput, qint64 nRVA)
{
    RESULT result = {};
    QFile file;

    if (_openCopy(sInput, sOutput, &file, &result)) {
        XPE pe(&file);
        quint32 nOld = pe.getOptionalHeader_AddressOfEntryPoint();
        pe.setOptionalHeader_AddressOfEntryPoint((quint32)nRVA);
        pe.fixCheckSum();
        result.listLog.append(QString("AddressOfEntryPoint 0x%1 -> 0x%2").arg(nOld, 0, 16).arg(nRVA, 0, 16));
        result.bSuccess = true;
        file.close();
    }

    return result;
}

HelperPeSurgery::RESULT HelperPeSurgery::stripOverlay(const QString &sInput, const QString &sOutput)
{
    RESULT result = {};
    QFile file;

    if (_openCopy(sInput, sOutput, &file, &result)) {
        XPE pe(&file);

        if (!pe.isOverlayPresent()) {
            result.sError = QString("The file has no overlay");
        } else {
            qint64 nSize = pe.getOverlaySize();
            result.bSuccess = pe.removeOverlay();
            result.listLog.append(QString("Removed overlay of %1 bytes at 0x%2").arg(nSize).arg(pe.getOverlayOffset(), 0, 16));
        }

        file.close();

        if (!result.bSuccess) {
            QFile::remove(sOutput);
        }
    }

    return result;
}

HelperPeSurgery::RESULT HelperPeSurgery::saveRange(const QString &sInput, const QString &sOutput, qint64 nOffset, qint64 nSize)
{
    RESULT result = {};
    QFile fileIn(sInput);

    if (!fileIn.open(QIODevice::ReadOnly)) {
        result.sError = QString("Cannot open %1").arg(sInput);
        return result;
    }

    nOffset = qBound<qint64>(0, nOffset, fileIn.size());
    nSize = qBound<qint64>(0, nSize, fileIn.size() - nOffset);

    QFile fileOut(sOutput);

    if (!fileOut.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        result.sError = QString("Cannot create %1").arg(sOutput);
        return result;
    }

    fileIn.seek(nOffset);
    qint64 nLeft = nSize;

    while (nLeft > 0) {
        QByteArray baChunk = fileIn.read(qMin<qint64>(nLeft, 0x100000));

        if (baChunk.isEmpty()) {
            break;
        }

        fileOut.write(baChunk);
        nLeft -= baChunk.size();
    }

    result.bSuccess = (nLeft == 0);
    result.listLog.append(QString("Saved 0x%1 bytes from offset 0x%2 to %3").arg(nSize, 0, 16).arg(nOffset, 0, 16).arg(sOutput));

    return result;
}

HelperPeSurgery::RESULT HelperPeSurgery::restoreSectionFlags(const QString &sInput, const QString &sOutput)
{
    RESULT result = {};
    QFile file;

    if (_openCopy(sInput, sOutput, &file, &result)) {
        XPE pe(&file);
        QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();
        qint32 nEntryPointSection = pe.getEntryPointSection();
        static const QSet<QString> stCode = {".text", "CODE", ".itext", ".textbss"};
        static const QSet<QString> stData = {".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".idata", ".edata", ".tls", ".bss", "DATA", "BSS", ".CRT"};
        const quint32 nW = XPE_DEF::S_IMAGE_SCN_MEM_WRITE;
        const quint32 nX = XPE_DEF::S_IMAGE_SCN_MEM_EXECUTE;
        qint32 nChanged = 0;

        for (qint32 i = 0; i < listSections.count(); i++) {
            quint32 nOld = listSections.at(i).Characteristics;
            QString sName = _sectionName(listSections.at(i));
            quint32 nNew = nOld;

            if ((nOld & nW) && (nOld & nX)) {
                if ((i == nEntryPointSection) || stCode.contains(sName)) {
                    nNew = nOld & ~nW;  // code: read + execute
                } else if (stData.contains(sName)) {
                    nNew = nOld & ~nX;  // data: read + write
                }
            }

            if (nNew != nOld) {
                pe.setSection_Characteristics(i, nNew);
                result.listLog.append(QString("%1: %2 -> %3").arg(sName, _flags(nOld), _flags(nNew)));
                nChanged++;
            }
        }

        if (nChanged) {
            pe.fixCheckSum();
            result.bSuccess = true;
        } else {
            result.sError = QString("No RWX section with a recognisable role (code/data) to fix");
        }

        file.close();

        if (!result.bSuccess) {
            QFile::remove(sOutput);
        }
    }

    return result;
}

HelperPeSurgery::RESULT HelperPeSurgery::renameSection(const QString &sInput, const QString &sOutput, qint32 nSection, const QString &sName)
{
    RESULT result = {};
    QFile file;

    if (_openCopy(sInput, sOutput, &file, &result)) {
        XPE pe(&file);
        QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders();

        if ((nSection < 0) || (nSection >= listSections.count())) {
            result.sError = QString("No section #%1").arg(nSection);
        } else {
            QString sOld = _sectionName(listSections.at(nSection));
            pe.setSection_NameAsString(nSection, sName.left(8));
            result.listLog.append(QString("Section #%1: \"%2\" -> \"%3\"").arg(nSection).arg(sOld, sName.left(8)));
            result.bSuccess = true;
        }

        file.close();

        if (!result.bSuccess) {
            QFile::remove(sOutput);
        }
    }

    return result;
}

HelperPeSurgery::RESULT HelperPeSurgery::removeTls(const QString &sInput, const QString &sOutput)
{
    RESULT result = {};
    QFile file;

    if (_openCopy(sInput, sOutput, &file, &result)) {
        XPE pe(&file);
        XPE_DEF::IMAGE_DATA_DIRECTORY directory = pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_TLS);

        if ((directory.VirtualAddress == 0) && (directory.Size == 0)) {
            result.sError = QString("The file has no TLS directory");
        } else {
            QList<XADDR> listCallbacks = pe.getTLS_CallbacksList();
            XPE_DEF::IMAGE_DATA_DIRECTORY empty = {};
            pe.setOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_TLS, &empty);
            pe.fixCheckSum();
            result.listLog.append(QString("Cleared the TLS directory (RVA 0x%1, size 0x%2); %3 callback(s) will no longer run")
                                      .arg(directory.VirtualAddress, 0, 16)
                                      .arg(directory.Size, 0, 16)
                                      .arg(listCallbacks.count()));
            result.listLog.append(QString("Note: code that uses TLS variables (__declspec(thread)) may misbehave in this copy"));
            result.bSuccess = true;
        }

        file.close();

        if (!result.bSuccess) {
            QFile::remove(sOutput);
        }
    }

    return result;
}

HelperPeSurgery::RESULT HelperPeSurgery::fixChecksum(const QString &sInput, const QString &sOutput)
{
    RESULT result = {};
    QFile file;

    if (_openCopy(sInput, sOutput, &file, &result)) {
        XPE pe(&file);
        quint32 nOld = pe.getOptionalHeader_CheckSum();
        pe.fixCheckSum();
        result.listLog.append(QString("CheckSum 0x%1 -> 0x%2").arg(nOld, 8, 16, QChar('0')).arg(pe.getOptionalHeader_CheckSum(), 8, 16, QChar('0')));
        result.bSuccess = true;
        file.close();
    }

    return result;
}
