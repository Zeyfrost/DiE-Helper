// DiE Helper (fork addition): static search for compressed blobs in a file and blind decompression
// (NRV2B/2D/2E, LZMA, aPLib, zlib, raw deflate, LZNT1). Nothing is executed, loaded or emulated:
// candidates are found from section entropy, from addresses that the first instructions at the entry
// point reference (static disassembly only) and from the overlay; every decoder is bounds-checked,
// output-capped and time-limited.
#ifndef HELPERDECOMPRESSOR_H
#define HELPERDECOMPRESSOR_H

#include <QByteArray>
#include <QList>
#include <QStringList>

#include "xbinary.h"

class HelperDecompressor {
public:
    enum ALGO {
        ALGO_NRV2B = 0,
        ALGO_NRV2D,
        ALGO_NRV2E,
        ALGO_LZMA,
        ALGO_APLIB,
        ALGO_ZLIB,
        ALGO_DEFLATE,
        ALGO_LZNT1
    };

    struct BLOB {
        ALGO algo;
        qint64 nOffset;          // file offset of the compressed stream (header included)
        qint64 nCompressedSize;  // bytes the decoder consumed
        QByteArray baData;       // decompressed data
        qint32 nScore;           // 0..100
        QString sDetails;
        QString sSection;        // section name, "overlay", "headers" or "file"
    };

    struct RESULT {
        bool bIsValid;
        QString sError;
        QList<BLOB> listBlobs;  // score desc, at most 10
        QStringList listLog;
    };

    // Searches sFileName for compressed streams. pPdStruct (optional) is only polled for cancellation.
    static RESULT scan(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct = nullptr);
    // Decodes one stream that starts at baInput[0]. Returns true only when the stream decoded
    // consistently (end marker / end of stream / declared size reached, or nMaxOutput reached).
    // *pnConsumed receives the number of input bytes that belong to the stream.
    // ALGO_LZMA accepts a 13-byte .lzma "alone" header or 5 property bytes followed by the stream;
    // ALGO_APLIB accepts a plain stream or one with an "AP32" safe header;
    // NRV2x tries the 32-bit little-endian bit buffer (UPX x86/x64 stubs) first, then the 8-bit one.
    static bool decompress(ALGO algo, const QByteArray &baInput, QByteArray *pbaOutput, qint64 nMaxOutput, qint64 *pnConsumed = nullptr);
    static QString algoToString(ALGO algo);
};

#endif  // HELPERDECOMPRESSOR_H
