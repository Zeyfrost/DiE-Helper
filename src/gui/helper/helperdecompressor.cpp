// DiE Helper (fork addition): static search for compressed blobs and blind, bounds-checked decompression.
#include "helperdecompressor.h"

#include <QElapsedTimer>
#include <QFile>
#include <QMap>
#include <QSet>
#include <QtEndian>
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <new>

#include "xdisasmcore.h"
#include "xpe.h"

// Last on purpose: the 7-Zip/zlib declarations in here bring a lot of C macros and typedefs.
#include "xalgo_local.h"

namespace {

const qint64 N_HELPER_MAX_OUTPUT = 64ll << 20;       // per decoded blob
const qint64 N_HELPER_MAX_FILE = 256ll << 20;        // larger files are not scanned
const qint64 N_HELPER_MAX_INPUT = 128ll << 20;       // per attempt
const qint64 N_HELPER_SCAN_BUDGET_MS = 30000;        // whole scan
const qint64 N_HELPER_ATTEMPT_BUDGET_MS = 5000;      // one (candidate, algorithm) attempt
const qint64 N_HELPER_DECOMPRESS_BUDGET_MS = 15000;  // public decompress()
const qint32 N_HELPER_EP_INSTRUCTIONS = 2000;
const qint64 N_HELPER_MIN_OUTPUT = 1024;
const qint32 N_HELPER_MAX_BLOBS = 10;

// Time / cancellation guard shared by all decoders. The caller's PDSTRUCT is only polled: putting a
// deadline on it (XBinary::setPdStructDeadline) would set bIsStop on expiry and stop the caller's whole task.
struct DECODE_CONTEXT {
    XBinary::PDSTRUCT *pPdStruct;
    QElapsedTimer timer;
    qint64 nBudgetMs;
    quint32 nTick;
};

bool _isAlive(DECODE_CONTEXT *pContext)
{
    if (!XBinary::isPdStructNotCanceled(pContext->pPdStruct)) {
        return false;
    }

    return pContext->timer.elapsed() < pContext->nBudgetMs;
}

// Cheap variant for inner loops: really checks only every 64K calls
bool _tick(DECODE_CONTEXT *pContext)
{
    pContext->nTick++;

    if ((pContext->nTick & 0xFFFF) == 0) {
        return _isAlive(pContext);
    }

    return true;
}

// Growing output buffer with a hard cap
struct OUTBUF {
    QByteArray *pbaData;
    qint64 nSize;
    qint64 nMax;

    bool reserve(qint64 nTotal)
    {
        if ((nTotal < 0) || (nTotal > nMax)) {
            return false;
        }

        if (nTotal > (qint64)pbaData->size()) {
            qint64 nNew = qMax<qint64>(nTotal, qMin<qint64>(nMax, qMax<qint64>(0x10000, (qint64)pbaData->size() * 2)));
            pbaData->resize((qsizetype)nNew);

            if ((qint64)pbaData->size() < nNew) {
                return false;
            }
        }

        return true;
    }

    bool put(quint8 nByte)
    {
        if (!reserve(nSize + 1)) {
            return false;
        }

        pbaData->data()[nSize++] = (char)nByte;

        return true;
    }

    bool append(const quint8 *pData, qint64 nLength)
    {
        if (!reserve(nSize + nLength)) {
            return false;
        }

        memcpy(pbaData->data() + nSize, pData, (size_t)nLength);
        nSize += nLength;

        return true;
    }

    // LZ77 copy; overlapping copies (nOffset < nLength) must go byte by byte
    bool copyMatch(qint64 nOffset, qint64 nLength)
    {
        if ((nOffset <= 0) || (nOffset > nSize) || (nLength < 0) || !reserve(nSize + nLength)) {
            return false;
        }

        char *pData = pbaData->data();

        for (qint64 i = 0; i < nLength; i++) {
            pData[nSize] = pData[nSize - nOffset];
            nSize++;
        }

        return true;
    }

    char *tail()
    {
        return pbaData->data() + nSize;
    }

    void finish()
    {
        pbaData->resize((qsizetype)nSize);
    }
};

double _entropy(const quint8 *pData, qint64 nSize)
{
    if (nSize <= 0) {
        return 0;
    }

    qint64 nCounts[256] = {};

    for (qint64 i = 0; i < nSize; i++) {
        nCounts[pData[i]]++;
    }

    double dResult = 0;

    for (qint32 i = 0; i < 256; i++) {
        if (nCounts[i]) {
            double dP = (double)nCounts[i] / (double)nSize;
            dResult -= dP * std::log2(dP);
        }
    }

    return dResult;
}

// ---------------------------------------------------------------------------------------------
// NRV2B / NRV2D / NRV2E (UCL). Own bounds-checked implementation: XUCLDecoder needs the exact output
// size, which a blind scan does not know. Bit streams and token layout follow the reference decoders
// ucl_nrv2{b,d,e}_decompress_{8,le32} in dep/XArchive/Algos/xucldecoder.cpp (UCL by Markus Oberhumer).
// ---------------------------------------------------------------------------------------------
enum NRVKIND {
    NRVKIND_2B = 0,
    NRVKIND_2D,
    NRVKIND_2E
};

struct NRV_BITREADER {
    const quint8 *pSrc;
    qint64 nSrcLen;
    qint64 nPos;
    quint32 nBB;
    qint32 nBC;
    bool bLe32;
    bool bError;

    quint32 getBit()
    {
        if (bLe32) {
            // getbit_le32: 32-bit little-endian words, MSB first
            if (nBC > 0) {
                nBC--;
                return (nBB >> nBC) & 1;
            }

            if (nPos + 4 > nSrcLen) {
                bError = true;
                return 0;
            }

            nBB = qFromLittleEndian<quint32>(pSrc + nPos);
            nPos += 4;
            nBC = 31;

            return (nBB >> 31) & 1;
        }

        // getbit_8: bb *= 2, refill with src[ilen++] * 2 + 1 when the low byte runs empty
        nBB *= 2;

        if (nBB & 0xFF) {
            return (nBB >> 8) & 1;
        }

        if (nPos >= nSrcLen) {
            bError = true;
            return 0;
        }

        nBB = (quint32)pSrc[nPos++] * 2 + 1;

        return (nBB >> 8) & 1;
    }
};

bool _nrvDecode(NRVKIND kind, bool bLe32, const quint8 *pSrc, qint64 nSrcLen, QByteArray *pbaOutput, qint64 nMaxOutput, qint64 *pnConsumed,
                DECODE_CONTEXT *pContext)
{
    NRV_BITREADER reader = {pSrc, nSrcLen, 0, 0, 0, bLe32, false};
    OUTBUF out = {pbaOutput, 0, nMaxOutput};
    quint32 nLastOff = 1;
    const quint32 nFarLimit = (kind == NRVKIND_2B) ? 0xD00 : 0x500;
    bool bDone = false;

    pbaOutput->clear();

    while (!bDone) {
        if (!_tick(pContext)) {
            return false;
        }

        // literals
        while (reader.getBit()) {
            if (reader.bError || (reader.nPos >= nSrcLen) || !out.put(pSrc[reader.nPos++])) {
                return false;
            }

            if (!_tick(pContext)) {
                return false;
            }
        }

        if (reader.bError) {
            return false;
        }

        // match offset (gamma code)
        quint32 nOff = 1;
        quint32 nLen = 0;

        if (kind == NRVKIND_2B) {
            do {
                nOff = nOff * 2 + reader.getBit();

                if (reader.bError || (nOff > 0xFFFFFF + 3)) {
                    return false;
                }
            } while (!reader.getBit());
        } else {
            for (;;) {
                nOff = nOff * 2 + reader.getBit();

                if (reader.bError || (nOff > 0xFFFFFF + 3)) {
                    return false;
                }

                if (reader.getBit()) {
                    break;
                }

                nOff = (nOff - 1) * 2 + reader.getBit();
            }
        }

        if (reader.bError) {
            return false;
        }

        if (nOff == 2) {
            nOff = nLastOff;

            if (kind != NRVKIND_2B) {
                nLen = reader.getBit();
            }
        } else {
            if (reader.nPos >= nSrcLen) {
                return false;
            }

            nOff = (nOff - 3) * 256 + pSrc[reader.nPos++];

            if (nOff == 0xFFFFFFFF) {
                bDone = true;  // end marker
                break;
            }

            if (kind != NRVKIND_2B) {
                nLen = (nOff ^ 0xFFFFFFFF) & 1;
                nOff >>= 1;
            }

            nLastOff = ++nOff;
        }

        // match length
        if (kind == NRVKIND_2E) {
            if (nLen) {
                nLen = 1 + reader.getBit();
            } else if (reader.getBit()) {
                nLen = 3 + reader.getBit();
            } else {
                nLen = 1;

                do {
                    nLen = nLen * 2 + reader.getBit();

                    if (reader.bError || ((qint64)nLen >= nMaxOutput)) {
                        return false;
                    }
                } while (!reader.getBit());

                nLen += 3;
            }
        } else {
            if (kind == NRVKIND_2B) {
                nLen = reader.getBit();
            }

            nLen = nLen * 2 + reader.getBit();

            if (nLen == 0) {
                nLen = 1;

                do {
                    nLen = nLen * 2 + reader.getBit();

                    if (reader.bError || ((qint64)nLen >= nMaxOutput)) {
                        return false;
                    }
                } while (!reader.getBit());

                nLen += 2;
            }
        }

        if (reader.bError) {
            return false;
        }

        nLen += (nOff > nFarLimit) ? 1 : 0;

        // the reference copies m_len + 1 bytes
        if (!out.copyMatch(nOff, (qint64)nLen + 1)) {
            return false;
        }
    }

    out.finish();

    if (pnConsumed) {
        *pnConsumed = reader.nPos;
    }

    return bDone;
}

// ---------------------------------------------------------------------------------------------
// aPLib depacker, copied from dep/XStaticUnpacker/xenigmavb.cpp evbAplibDepack()
// (DIE-engine, MIT License, Copyright (c) 2017-2026 hors <horsicq@gmail.com>; the algorithm is
// Joergen Ibsen's public-domain aP_depack).
// DiE Helper changes: output capped at nMaxOutput instead of an exact expected size; the end marker
// alone ends a successful decode (trailing input is allowed and reported through *pnConsumed);
// cancellation through DECODE_CONTEXT instead of a PDSTRUCT poll per bit.
// ---------------------------------------------------------------------------------------------
bool _aplibDepack(const quint8 *pSrc, qint64 nSrcLen, qint64 nMaxOutput, QByteArray *pOut, qint64 *pnConsumed, DECODE_CONTEXT *pContext)
{
    if (!pSrc || !pOut || (nSrcLen <= 0) || (nMaxOutput <= 0)) {
        return false;
    }

    pOut->clear();

    qint64 nPos = 0;
    quint8 nTag = 0;
    qint32 nBitCount = 0;
    bool bAlive = true;

    struct GET_BIT {
        const quint8 *pSource;
        qint64 nSourceLength;
        qint64 *pPosition;
        quint8 *pTag;
        qint32 *pBitCount;
        DECODE_CONTEXT *pContext;
        bool *pbAlive;
        qint32 operator()() const
        {
            if (!_tick(pContext)) {
                *pbAlive = false;
                return -1;
            }
            if (*pBitCount == 0) {
                if (*pPosition >= nSourceLength) return -1;
                *pTag = pSource[(*pPosition)++];
                *pBitCount = 8;
            }
            const qint32 nBit = (*pTag >> 7) & 1;
            *pTag = static_cast<quint8>(*pTag << 1);
            --(*pBitCount);
            return nBit;
        }
    };
    const GET_BIT getBit = {pSrc, nSrcLen, &nPos, &nTag, &nBitCount, pContext, &bAlive};

    struct GET_GAMMA {
        const GET_BIT *pGetBit;
        qint64 nMaxOutput;
        bool operator()(quint64 *pnValue) const
        {
            if (!pnValue) return false;
            quint64 nValue = 1;
            for (;;) {
                const qint32 nBit = (*pGetBit)();
                if (nBit < 0) return false;
                if (nValue > (static_cast<quint64>(nMaxOutput) - static_cast<quint64>(nBit)) / 2) return false;
                nValue = nValue * 2 + static_cast<quint64>(nBit);
                const qint32 nContinue = (*pGetBit)();
                if (nContinue < 0) return false;
                if (!nContinue) break;
            }
            *pnValue = nValue;
            return true;
        }
    };
    const GET_GAMMA getGamma = {&getBit, nMaxOutput};

    struct APPEND_BYTE {
        QByteArray *pOutput;
        qint64 nMaxOutput;
        bool operator()(quint8 nByte) const
        {
            if (static_cast<qint64>(pOutput->size()) >= nMaxOutput) return false;
            pOutput->append(static_cast<char>(nByte));
            return true;
        }
    };
    const APPEND_BYTE appendByte = {pOut, nMaxOutput};

    struct COPY_MATCH {
        QByteArray *pOutput;
        qint64 nMaxOutput;
        bool operator()(quint64 nOffset, quint64 nLength) const
        {
            if ((nOffset == 0) || (nOffset > static_cast<quint64>(pOutput->size())) || (nLength > static_cast<quint64>(nMaxOutput - pOutput->size()))) {
                return false;
            }
            for (quint64 i = 0; i < nLength; i++) {
                pOutput->append(pOutput->at(pOutput->size() - static_cast<qsizetype>(nOffset)));
            }
            return true;
        }
    };
    const COPY_MATCH copyMatch = {pOut, nMaxOutput};

    if (!appendByte(pSrc[nPos++])) return false;

    quint64 nR0 = 0;
    qint32 nLwm = 0;
    bool bDone = false;

    while (!bDone && bAlive) {
        const qint32 b0 = getBit();
        if (b0 < 0) return false;
        if (b0) {
            const qint32 b1 = getBit();
            if (b1 < 0) return false;
            if (b1) {
                const qint32 b2 = getBit();
                if (b2 < 0) return false;
                if (b2) {
                    quint64 nOffset = 0;
                    for (qint32 i = 0; i < 4; i++) {
                        const qint32 nBit = getBit();
                        if (nBit < 0) return false;
                        nOffset = nOffset * 2 + (quint64)nBit;
                    }
                    if (nOffset) {
                        if (!copyMatch(nOffset, 1)) return false;
                    } else if (!appendByte(0)) {
                        return false;
                    }
                    nLwm = 0;
                } else {
                    if (nPos >= nSrcLen) return false;
                    const quint8 nByte = pSrc[nPos++];
                    const quint64 nLength = 2 + (nByte & 1);
                    const quint64 nOffset = nByte >> 1;
                    if (nOffset == 0) {
                        bDone = true;
                    } else if (!copyMatch(nOffset, nLength)) {
                        return false;
                    }
                    nR0 = nOffset;
                    nLwm = 1;
                }
            } else {
                quint64 nOffsetCode = 0;
                if (!getGamma(&nOffsetCode)) return false;

                if ((nLwm == 0) && (nOffsetCode == 2)) {
                    quint64 nLength = 0;
                    if (!getGamma(&nLength) || !copyMatch(nR0, nLength)) return false;
                } else {
                    const quint64 nDelta = (nLwm == 0) ? 3 : 2;
                    if ((nOffsetCode < nDelta) || (nPos >= nSrcLen)) return false;
                    const quint64 nOffsetHigh = nOffsetCode - nDelta;
                    if (nOffsetHigh > (quint64)nMaxOutput / 256) return false;
                    const quint64 nOffset = nOffsetHigh * 256 + pSrc[nPos++];

                    quint64 nLength = 0;
                    if (!getGamma(&nLength)) return false;
                    if (nOffset >= 32000) nLength++;
                    if (nOffset >= 1280) nLength++;
                    if (nOffset < 128) nLength += 2;
                    if (!copyMatch(nOffset, nLength)) return false;
                    nR0 = nOffset;
                }
                nLwm = 1;
            }
        } else {
            if (nPos >= nSrcLen || !appendByte(pSrc[nPos++])) return false;
            nLwm = 0;
        }
    }

    if (pnConsumed) {
        *pnConsumed = nPos;
    }

    return bDone && bAlive;
}

// ---------------------------------------------------------------------------------------------
// LZMA through the 7-Zip decoder that DIE-engine already links (X_LzmaDec_*, xalgo_local.h)
// ---------------------------------------------------------------------------------------------
void *_lzmaAlloc(ISzAllocPtr pAlloc, size_t nSize)
{
    Q_UNUSED(pAlloc)
    return malloc(nSize);
}

void _lzmaFree(ISzAllocPtr pAlloc, void *pAddress)
{
    Q_UNUSED(pAlloc)
    free(pAddress);
}

const ISzAlloc g_helperLzmaAlloc = {_lzmaAlloc, _lzmaFree};

// Encoders (7-Zip SDK, xz-utils, Python) write 2^n or 3 * 2^(n-1); random bytes almost never match.
bool _isLzmaDictSize(quint32 nDict)
{
    if ((nDict < 0x1000) || (nDict > 0x60000000)) {
        return false;
    }

    for (qint32 i = 12; i <= 30; i++) {
        if ((nDict == (1u << i)) || (nDict == (3u << (i - 1)))) {
            return true;
        }
    }

    return false;
}

bool _lzmaDecode(const quint8 *pSrc, qint64 nSrcLen, bool bHeader13, QByteArray *pbaOutput, qint64 nMaxOutput, qint64 *pnConsumed, bool *pbClean,
                 DECODE_CONTEXT *pContext)
{
    const qint64 nHeaderSize = bHeader13 ? 13 : 5;

    if (nSrcLen <= nHeaderSize) {
        return false;
    }

    if (pSrc[0] >= 9 * 5 * 5) {
        return false;
    }

    quint32 nDict = qFromLittleEndian<quint32>(pSrc + 1);

    if (!_isLzmaDictSize(nDict)) {
        return false;
    }

    qint64 nKnownSize = -1;

    if (bHeader13) {
        quint64 nSize = qFromLittleEndian<quint64>(pSrc + 5);

        if (nSize != 0xFFFFFFFFFFFFFFFFULL) {
            if ((nSize == 0) || (nSize > (quint64)nMaxOutput)) {
                return false;
            }

            nKnownSize = (qint64)nSize;
        }
    }

    // Distances never exceed the output produced so far, so the dictionary can be capped at the output limit.
    quint8 props[5];
    props[0] = pSrc[0];
    qint64 nDictCap = (nKnownSize > 0) ? nKnownSize : nMaxOutput;
    qToLittleEndian<quint32>((quint32)qMax<qint64>(0x1000, qMin<qint64>(nDict, nDictCap)), props + 1);

    CLzmaDec state;
    X_LzmaDec_Construct(&state);

    if (X_LzmaDec_Allocate(&state, props, 5, &g_helperLzmaAlloc) != SZ_OK) {
        return false;
    }

    X_LzmaDec_Init(&state);

    pbaOutput->clear();
    OUTBUF out = {pbaOutput, 0, nMaxOutput};
    qint64 nInPos = nHeaderSize;
    qint64 nLimit = (nKnownSize >= 0) ? nKnownSize : nMaxOutput;
    bool bResult = false;
    bool bClean = false;

    for (;;) {
        if (!_isAlive(pContext)) {
            break;
        }

        qint64 nChunk = qMin<qint64>(0x100000, nLimit - out.nSize);

        if (nChunk <= 0) {
            bResult = true;  // declared size (clean) or output cap reached
            bClean = (nKnownSize >= 0);
            break;
        }

        if (!out.reserve(out.nSize + nChunk)) {
            break;
        }

        SizeT nDest = (SizeT)nChunk;
        SizeT nSource = (SizeT)qMin<qint64>(nSrcLen - nInPos, 0x40000000);
        ELzmaStatus status = LZMA_STATUS_NOT_SPECIFIED;
        SRes nRes = X_LzmaDec_DecodeToBuf(&state, (Byte *)out.tail(), &nDest, pSrc + nInPos, &nSource, LZMA_FINISH_ANY, &status);

        out.nSize += (qint64)nDest;
        nInPos += (qint64)nSource;

        if (nRes != SZ_OK) {
            // 5-byte form has no size and often no end marker: the stub knows the size, we do not.
            // Keep what decoded before the data error; the tail may contain garbage.
            bResult = (!bHeader13) && (out.nSize >= N_HELPER_MIN_OUTPUT);
            break;
        }

        if (status == LZMA_STATUS_FINISHED_WITH_MARK) {
            bResult = true;
            bClean = true;
            break;
        }

        if ((nDest == 0) && (nSource == 0)) {
            if (status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK) {
                bResult = true;
                bClean = true;
            } else {
                bResult = (!bHeader13) && (out.nSize >= N_HELPER_MIN_OUTPUT);
            }

            break;
        }
    }

    X_LzmaDec_Free(&state, &g_helperLzmaAlloc);

    out.finish();

    if (pnConsumed) {
        *pnConsumed = nInPos;
    }

    if (pbClean) {
        *pbClean = bClean;
    }

    return bResult && (out.nSize > 0);
}

// ---------------------------------------------------------------------------------------------
// zlib (RFC 1950) and raw deflate (RFC 1951) through the zlib that DIE-engine links (X_inflate*)
// ---------------------------------------------------------------------------------------------
bool _inflate(const quint8 *pSrc, qint64 nSrcLen, bool bRaw, QByteArray *pbaOutput, qint64 nMaxOutput, qint64 *pnConsumed, bool *pbClean,
              DECODE_CONTEXT *pContext)
{
    if (!bRaw) {
        // CMF/FLG: deflate, window <= 32K, header checksum
        if ((nSrcLen < 6) || ((pSrc[0] & 0x0F) != 8) || ((pSrc[0] >> 4) > 7) || ((((quint32)pSrc[0] << 8) | pSrc[1]) % 31 != 0)) {
            return false;
        }
    } else if (nSrcLen < 2) {
        return false;
    }

    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    if (X_inflateInit2(&stream, bRaw ? -MAX_WBITS : MAX_WBITS) != Z_OK) {
        return false;
    }

    pbaOutput->clear();
    OUTBUF out = {pbaOutput, 0, nMaxOutput};
    stream.next_in = (Bytef *)pSrc;
    stream.avail_in = (uInt)qMin<qint64>(nSrcLen, 0x7FFFFFFF);
    bool bResult = false;
    bool bClean = false;

    for (;;) {
        if (!_isAlive(pContext)) {
            break;
        }

        qint64 nChunk = qMin<qint64>(0x100000, nMaxOutput - out.nSize);

        if (nChunk <= 0) {
            bResult = true;  // output cap reached
            break;
        }

        if (!out.reserve(out.nSize + nChunk)) {
            break;
        }

        stream.next_out = (Bytef *)out.tail();
        stream.avail_out = (uInt)nChunk;

        int nRet = X_inflate(&stream, Z_NO_FLUSH);
        qint64 nProduced = nChunk - (qint64)stream.avail_out;
        out.nSize += nProduced;

        if (nRet == Z_STREAM_END) {
            bResult = true;
            bClean = true;
            break;
        }

        if ((nRet != Z_OK) || ((nProduced == 0) && (stream.avail_in == 0))) {
            break;  // data error, or input ended without the final block
        }
    }

    if (pnConsumed) {
        *pnConsumed = (qint64)stream.total_in;
    }

    X_inflateEnd(&stream);

    out.finish();

    if (pbClean) {
        *pbClean = bClean;
    }

    return bResult && (out.nSize > 0);
}

// ---------------------------------------------------------------------------------------------
// LZNT1 (RtlDecompressBuffer COMPRESSION_FORMAT_LZNT1). Own implementation from the published format
// ([MS-XCA] 2.5): 16-bit chunk header (bits 0-11 = data size - 1, bits 12-14 = signature 3,
// bit 15 = compressed), each chunk decodes to at most 4096 bytes; inside a compressed chunk a flag byte
// covers 8 tokens (LSB first), a set bit is a 16-bit back-reference whose offset/length split depends
// on the position inside the chunk. A zero header ends the stream.
// ---------------------------------------------------------------------------------------------
bool _lznt1Decode(const quint8 *pSrc, qint64 nSrcLen, QByteArray *pbaOutput, qint64 nMaxOutput, qint64 *pnConsumed, bool *pbClean, DECODE_CONTEXT *pContext)
{
    pbaOutput->clear();
    OUTBUF out = {pbaOutput, 0, nMaxOutput};
    qint64 nPos = 0;
    qint32 nChunks = 0;
    bool bClean = false;

    while (nPos + 2 <= nSrcLen) {
        if (!_isAlive(pContext)) {
            break;
        }

        quint16 nHeader = qFromLittleEndian<quint16>(pSrc + nPos);

        if (nHeader == 0) {
            nPos += 2;
            bClean = true;
            break;
        }

        if (((nHeader >> 12) & 7) != 3) {
            break;  // not a chunk header: end of the stream (no terminator) or garbage
        }

        qint64 nChunkSize = (nHeader & 0x0FFF) + 1;

        if (nPos + 2 + nChunkSize > nSrcLen) {
            break;
        }

        const quint8 *pChunk = pSrc + nPos + 2;
        qint64 nChunkStart = out.nSize;
        bool bChunkOk = true;

        if (!(nHeader & 0x8000)) {
            bChunkOk = (nChunkSize <= 4096) && out.append(pChunk, nChunkSize);
        } else {
            qint64 i = 0;

            while (bChunkOk && (i < nChunkSize)) {
                quint8 nFlags = pChunk[i++];

                for (qint32 nBit = 0; bChunkOk && (nBit < 8) && (i < nChunkSize); nBit++) {
                    qint64 nChunkPos = out.nSize - nChunkStart;

                    if (!((nFlags >> nBit) & 1)) {
                        bChunkOk = (nChunkPos < 4096) && out.put(pChunk[i++]);
                    } else {
                        if ((i + 2 > nChunkSize) || (nChunkPos <= 0)) {
                            bChunkOk = false;
                            break;
                        }

                        quint16 nToken = qFromLittleEndian<quint16>(pChunk + i);
                        i += 2;

                        quint32 nLengthMask = 0x0FFF;
                        qint32 nOffsetShift = 12;

                        for (qint64 nP = nChunkPos - 1; nP >= 0x10; nP >>= 1) {
                            nLengthMask >>= 1;
                            nOffsetShift--;
                        }

                        qint64 nLength = (qint64)(nToken & nLengthMask) + 3;
                        qint64 nOffset = (qint64)(nToken >> nOffsetShift) + 1;

                        bChunkOk = (nOffset <= nChunkPos) && (nChunkPos + nLength <= 4096) && out.copyMatch(nOffset, nLength);
                    }
                }
            }
        }

        if (!bChunkOk) {
            out.nSize = nChunkStart;  // drop the broken chunk, keep the ones before it

            break;
        }

        nPos += 2 + nChunkSize;
        nChunks++;
    }

    if ((nChunks > 0) && (nPos == nSrcLen)) {
        bClean = true;
    }

    out.finish();

    if (pnConsumed) {
        *pnConsumed = nPos;
    }

    if (pbClean) {
        *pbClean = bClean;
    }

    return (nChunks > 0) && (out.nSize > 0);
}

// One attempt of one algorithm on pData; all variants of that algorithm are tried
bool _decode(HelperDecompressor::ALGO algo, const quint8 *pData, qint64 nSize, QByteArray *pbaOutput, qint64 nMaxOutput, qint64 *pnConsumed, bool *pbClean,
             QString *psVariant, DECODE_CONTEXT *pContext)
{
    bool bResult = false;
    qint64 nConsumed = 0;
    bool bClean = false;
    QString sVariant;

    if ((nSize <= 0) || !pData) {
        return false;
    }

    try {
        switch (algo) {
            case HelperDecompressor::ALGO_NRV2B:
            case HelperDecompressor::ALGO_NRV2D:
            case HelperDecompressor::ALGO_NRV2E: {
                NRVKIND kind = (algo == HelperDecompressor::ALGO_NRV2B) ? NRVKIND_2B : ((algo == HelperDecompressor::ALGO_NRV2D) ? NRVKIND_2D : NRVKIND_2E);

                if (_nrvDecode(kind, true, pData, nSize, pbaOutput, nMaxOutput, &nConsumed, pContext)) {
                    bResult = true;
                    sVariant = "32-bit LE bit buffer";
                } else if (_isAlive(pContext) && _nrvDecode(kind, false, pData, nSize, pbaOutput, nMaxOutput, &nConsumed, pContext)) {
                    bResult = true;
                    sVariant = "8-bit bit buffer";
                }

                bClean = bResult;  // only the end marker ends an NRV decode
                break;
            }
            case HelperDecompressor::ALGO_LZMA:
                if (_lzmaDecode(pData, nSize, true, pbaOutput, nMaxOutput, &nConsumed, &bClean, pContext)) {
                    bResult = true;
                    sVariant = ".lzma alone header (13 bytes)";
                } else if (_isAlive(pContext) && _lzmaDecode(pData, nSize, false, pbaOutput, nMaxOutput, &nConsumed, &bClean, pContext)) {
                    bResult = true;
                    sVariant = bClean ? "5 property bytes" : "5 property bytes, no end marker (tail may be garbage)";
                }
                break;
            case HelperDecompressor::ALGO_APLIB: {
                qint64 nSkip = 0;

                // aPLib "safe" header: 'AP32', header size, packed size, packed crc, original size, original crc
                if ((nSize > 24) && (memcmp(pData, "AP32", 4) == 0)) {
                    quint32 nHeaderSize = qFromLittleEndian<quint32>(pData + 4);

                    if ((nHeaderSize >= 24) && (nHeaderSize <= 64) && ((qint64)nHeaderSize < nSize)) {
                        nSkip = nHeaderSize;
                        sVariant = "AP32 header";
                    }
                }

                bResult = _aplibDepack(pData + nSkip, nSize - nSkip, nMaxOutput, pbaOutput, &nConsumed, pContext);
                nConsumed += nSkip;
                bClean = bResult;

                if (sVariant.isEmpty()) {
                    sVariant = "plain stream";
                }

                break;
            }
            case HelperDecompressor::ALGO_ZLIB:
                bResult = _inflate(pData, nSize, false, pbaOutput, nMaxOutput, &nConsumed, &bClean, pContext);
                sVariant = "zlib header";
                break;
            case HelperDecompressor::ALGO_DEFLATE:
                bResult = _inflate(pData, nSize, true, pbaOutput, nMaxOutput, &nConsumed, &bClean, pContext);
                sVariant = "raw deflate";
                break;
            case HelperDecompressor::ALGO_LZNT1:
                bResult = _lznt1Decode(pData, nSize, pbaOutput, nMaxOutput, &nConsumed, &bClean, pContext);
                sVariant = bClean ? "terminated" : "no terminator";
                break;
        }
    } catch (const std::bad_alloc &) {
        bResult = false;
    }

    if (!bResult) {
        pbaOutput->clear();
    }

    if (pnConsumed) {
        *pnConsumed = nConsumed;
    }

    if (pbClean) {
        *pbClean = bClean;
    }

    if (psVariant) {
        *psVariant = sVariant;
    }

    return bResult;
}

// Share of E8 rel32 calls whose target stays inside the buffer: high for x86/x64 code, ~0 for anything else
bool _looksLikeX86Code(const QByteArray &baData, qint32 *pnCalls)
{
    const quint8 *pData = (const quint8 *)baData.constData();
    qint64 nSize = baData.size();
    qint32 nTotal = 0;
    qint32 nInside = 0;

    for (qint64 i = 0; i + 5 <= nSize; i++) {
        if (pData[i] == 0xE8) {
            qint64 nTarget = i + 5 + (qint32)qFromLittleEndian<quint32>(pData + i + 1);
            nTotal++;

            if ((nTarget >= 0) && (nTarget < nSize)) {
                nInside++;
            }
        }
    }

    if (pnCalls) {
        *pnCalls = nInside;
    }

    return (nInside >= 8) && (nInside * 100 >= nTotal * 30);
}

bool _looksLikeMZ(const QByteArray &baData, bool *pbIsPE)
{
    *pbIsPE = false;

    if ((baData.size() < 0x40) || (baData.at(0) != 'M') || (baData.at(1) != 'Z')) {
        return false;
    }

    quint32 nLfanew = qFromLittleEndian<quint32>(baData.constData() + 0x3C);

    if ((nLfanew + 4 <= (quint32)baData.size()) && (memcmp(baData.constData() + nLfanew, "PE\0\0", 4) == 0)) {
        *pbIsPE = true;
    }

    return true;
}

struct REGION {
    qint64 nOffset;
    qint64 nSize;
    QString sName;
};

qint32 _regionIndex(const QList<REGION> &listRegions, qint64 nOffset)
{
    for (qint32 i = 0; i < listRegions.count(); i++) {
        if ((nOffset >= listRegions.at(i).nOffset) && (nOffset < listRegions.at(i).nOffset + listRegions.at(i).nSize)) {
            return i;
        }
    }

    return -1;
}

struct CANDIDATE {
    qint64 nOffset;
    qint64 nEnd;
    qint32 nPriority;  // lower = tried first
    QString sReason;
    QString sSection;
    bool bEpReference;
};

QString _sectionName(const XPE_DEF::IMAGE_SECTION_HEADER &header)
{
    return QString::fromLatin1((const char *)header.Name, (int)strnlen((const char *)header.Name, 8));
}

}  // namespace

QString HelperDecompressor::algoToString(ALGO algo)
{
    switch (algo) {
        case ALGO_NRV2B: return QString("NRV2B");
        case ALGO_NRV2D: return QString("NRV2D");
        case ALGO_NRV2E: return QString("NRV2E");
        case ALGO_LZMA: return QString("LZMA");
        case ALGO_APLIB: return QString("aPLib");
        case ALGO_ZLIB: return QString("zlib");
        case ALGO_DEFLATE: return QString("Deflate (raw)");
        case ALGO_LZNT1: return QString("LZNT1");
    }

    return QString("Unknown");
}

bool HelperDecompressor::decompress(ALGO algo, const QByteArray &baInput, QByteArray *pbaOutput, qint64 nMaxOutput, qint64 *pnConsumed)
{
    if (!pbaOutput) {
        return false;
    }

    nMaxOutput = qBound<qint64>(1, nMaxOutput, 1ll << 30);

    DECODE_CONTEXT context = {};
    context.pPdStruct = nullptr;
    context.nBudgetMs = N_HELPER_DECOMPRESS_BUDGET_MS;
    context.timer.start();

    return _decode(algo, (const quint8 *)baInput.constData(), baInput.size(), pbaOutput, nMaxOutput, pnConsumed, nullptr, nullptr, &context);
}

HelperDecompressor::RESULT HelperDecompressor::scan(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct)
{
    RESULT result = {};
    QFile file(sFileName);

    if (!file.open(QIODevice::ReadOnly)) {
        result.sError = QString("Cannot open %1").arg(sFileName);
        return result;
    }

    if (file.size() > N_HELPER_MAX_FILE) {
        result.sError = QString("File is larger than %1 MiB; not scanned").arg(N_HELPER_MAX_FILE >> 20);
        return result;
    }

    const QByteArray baFile = file.readAll();
    const quint8 *pFile = (const quint8 *)baFile.constData();
    const qint64 nFileSize = baFile.size();

    QList<REGION> listRegions;
    QMap<qint64, CANDIDATE> mapCandidates;
    qint32 nSectionCandidates = 0;
    qint32 nEpCandidates = 0;
    qint32 nOverlayCandidates = 0;

    auto addRegion = [&](qint64 nOffset, qint64 nSize, const QString &sName) {
        REGION region = {};
        region.nOffset = nOffset;
        region.nSize = nSize;
        region.sName = sName;
        listRegions.append(region);
    };

    auto addCandidate = [&](qint64 nOffset, qint32 nPriority, const QString &sReason, bool bEpReference) -> bool {
        qint32 nRegion = _regionIndex(listRegions, nOffset);

        if ((nOffset < 0) || (nOffset >= nFileSize) || (nRegion < 0)) {
            return false;
        }

        if (mapCandidates.contains(nOffset)) {
            CANDIDATE &candidate = mapCandidates[nOffset];

            if (nPriority < candidate.nPriority) {
                candidate.nPriority = nPriority;
            }

            if (!candidate.sReason.contains(sReason)) {
                candidate.sReason += "; " + sReason;
            }

            candidate.bEpReference |= bEpReference;

            return false;
        }

        CANDIDATE candidate = {};
        candidate.nOffset = nOffset;
        candidate.nEnd = listRegions.at(nRegion).nOffset + listRegions.at(nRegion).nSize;
        candidate.nPriority = nPriority;
        candidate.sReason = sReason;
        candidate.sSection = listRegions.at(nRegion).sName;
        candidate.bEpReference = bEpReference;
        mapCandidates.insert(nOffset, candidate);

        return true;
    };

    XPE pe(&file);

    if (pe.isValid()) {
        XBinary::_MEMORY_MAP memoryMap = pe.getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);
        QList<XPE_DEF::IMAGE_SECTION_HEADER> listSections = pe.getSectionHeaders(pPdStruct);
        qint64 nHeadersSize = qMin<qint64>(nFileSize, pe.getOptionalHeader_SizeOfHeaders());
        QList<double> listEntropy;

        // regions: headers, sections (raw data), overlay
        addRegion(0, nHeadersSize, QString("headers"));

        for (qint32 i = 0; i < listSections.count(); i++) {
            qint64 nOffset = listSections.at(i).PointerToRawData;
            qint64 nSize = listSections.at(i).SizeOfRawData;

            if ((nOffset <= 0) || (nOffset >= nFileSize) || (nSize <= 0)) {
                listEntropy.append(0);
                continue;
            }

            nSize = qMin<qint64>(nSize, nFileSize - nOffset);
            QString sName = _sectionName(listSections.at(i));

            if (sName.isEmpty()) {
                sName = QString("#%1").arg(i);
            }

            addRegion(nOffset, nSize, sName);
            listEntropy.append(_entropy(pFile + nOffset, nSize));
        }

        qint64 nOverlayOffset = -1;

        if (pe.isOverlayPresent(pPdStruct)) {
            nOverlayOffset = pe.getOverlayOffset(pPdStruct);

            if ((nOverlayOffset > 0) && (nOverlayOffset < nFileSize)) {
                addRegion(nOverlayOffset, nFileSize - nOverlayOffset, QString("overlay"));
            } else {
                nOverlayOffset = -1;
            }
        }

        // 1) starts of high-entropy sections
        for (qint32 i = 0; i < listSections.count(); i++) {
            qint64 nOffset = listSections.at(i).PointerToRawData;
            qint64 nSize = qMin<qint64>(listSections.at(i).SizeOfRawData, nFileSize - nOffset);

            if ((listEntropy.at(i) < 7.0) || (nSize < 64)) {
                continue;
            }

            QString sReason = QString("start of high-entropy section (%1)").arg(listEntropy.at(i), 0, 'f', 2);
            static const qint64 nDeltas[] = {0, 4, 8, 0x0C, 0x10, 0x20, 0x30, 0x40};

            for (qint64 nDelta : nDeltas) {
                if ((nDelta < nSize) && addCandidate(nOffset + nDelta, (nDelta == 0) ? 1 : 3, nDelta ? QString("%1 +0x%2").arg(sReason).arg(nDelta, 0, 16) : sReason, false)) {
                    nSectionCandidates++;
                }
            }

            // padding before the stream
            qint64 nFirst = 0;

            while ((nFirst < qMin<qint64>(nSize, 0x1000)) && (pFile[nOffset + nFirst] == 0)) {
                nFirst++;
            }

            if ((nFirst > 0) && (nFirst < qMin<qint64>(nSize, 0x1000))) {
                if (addCandidate(nOffset + nFirst, 2, QString("first non-zero byte of high-entropy section"), false)) {
                    nSectionCandidates++;
                }
            }
        }

        // 2) addresses / immediates referenced by the first instructions from the entry point
        XBinary::DM disasmMode = XBinary::getDisasmMode(&memoryMap);

        if ((disasmMode == XBinary::DM_X86_32) || (disasmMode == XBinary::DM_X86_64)) {
            XDisasmCore disasmCore;
            disasmCore.setMode(disasmMode);
            XDisasmAbstract::DISASM_OPTIONS disasmOptions = {};
            disasmOptions.bNoStrings = true;

            XADDR nImageBase = memoryMap.nModuleAddress;
            qint64 nImageSize = pe.getOptionalHeader_SizeOfImage();
            qint64 nSectionAlignment = qMax<qint64>(0x200, pe.getOptionalHeader_SectionAlignment());
            XADDR nEntryPoint = nImageBase + pe.getOptionalHeader_AddressOfEntryPoint();

            auto addReference = [&](quint64 nValue, XADDR nFrom) {
                XADDR nAddress = 0;

                if ((nValue >= nImageBase) && (nValue < nImageBase + (quint64)nImageSize)) {
                    nAddress = nValue;  // VA
                } else if ((nValue >= (quint64)nSectionAlignment) && (nValue < (quint64)nImageSize)) {
                    nAddress = nImageBase + nValue;  // RVA
                } else {
                    return;
                }

                qint64 nOffset = XBinary::addressToOffset(&memoryMap, nAddress);
                qint32 nRegion = _regionIndex(listRegions, nOffset);

                if ((nOffset < 0) || (nRegion < 0)) {
                    return;
                }

                qint64 nWindow = qMin<qint64>(4096, listRegions.at(nRegion).nOffset + listRegions.at(nRegion).nSize - nOffset);

                if ((nWindow < 256) || (_entropy(pFile + nOffset, nWindow) < 6.5)) {
                    return;
                }

                if (addCandidate(nOffset, 0, QString("referenced by the instruction at 0x%1").arg(nFrom, 0, 16), true)) {
                    nEpCandidates++;
                }
            };

            QList<XADDR> listQueue;
            QSet<XADDR> stVisited;
            qint32 nCount = 0;
            listQueue.append(nEntryPoint);

            while (!listQueue.isEmpty() && (nCount < N_HELPER_EP_INSTRUCTIONS) && XBinary::isPdStructNotCanceled(pPdStruct)) {
                XADDR nAddress = listQueue.takeFirst();

                while (nCount < N_HELPER_EP_INSTRUCTIONS) {
                    if (stVisited.contains(nAddress)) {
                        break;
                    }

                    qint64 nOffset = XBinary::addressToOffset(&memoryMap, nAddress);

                    if ((nOffset < 0) || (nOffset >= nFileSize)) {
                        break;  // not file-backed (e.g. the jump to the OEP in an empty section)
                    }

                    char buffer[32] = {};  // 16 opcode bytes + zero padding
                    memcpy(buffer, pFile + nOffset, (size_t)qMin<qint64>(16, nFileSize - nOffset));

                    XDisasmAbstract::DISASM_RESULT disasmResult = disasmCore.disAsm(buffer, 16, nAddress, disasmOptions);

                    if (!disasmResult.bIsValid || (disasmResult.nSize <= 0)) {
                        break;
                    }

                    stVisited.insert(nAddress);
                    nCount++;

                    if (disasmResult.nXrefToMemory) {
                        addReference(disasmResult.nXrefToMemory, nAddress);
                    }

                    if (((disasmResult.nImmSize == 4) || (disasmResult.nImmSize == 8)) && (disasmResult.nImmOffset + disasmResult.nImmSize <= 16) &&
                        (disasmResult.relType == XDisasmAbstract::RELTYPE_NONE)) {
                        quint64 nImm = (disasmResult.nImmSize == 8) ? qFromLittleEndian<quint64>(buffer + disasmResult.nImmOffset)
                                                                    : qFromLittleEndian<quint32>(buffer + disasmResult.nImmOffset);
                        addReference(nImm, nAddress);
                    }

                    if ((disasmResult.nDispSize == 4) && (disasmResult.nDispOffset + 4 <= 16)) {
                        addReference(qFromLittleEndian<quint32>(buffer + disasmResult.nDispOffset), nAddress);
                    }

                    if (disasmResult.bIsRet) {
                        break;
                    }

                    bool bRelative = (disasmResult.relType != XDisasmAbstract::RELTYPE_NONE) && disasmResult.nXrefToRelative;

                    if (disasmResult.bIsCondJmp || disasmResult.bIsCall) {
                        if (bRelative) {
                            listQueue.append(disasmResult.nXrefToRelative);
                        }
                    } else if (disasmResult.bIsJmp) {
                        if (bRelative) {
                            nAddress = disasmResult.nXrefToRelative;  // follow
                            continue;
                        }

                        break;  // indirect jump
                    }

                    nAddress += disasmResult.nSize;
                }
            }

            result.listLog.append(QString("Entry point walk: %1 instruction(s) from 0x%2").arg(nCount).arg(nEntryPoint, 0, 16));
        } else {
            result.listLog.append(QString("Entry point walk skipped: not x86/x64 code"));
        }

        // 3) overlay
        if (nOverlayOffset > 0) {
            static const qint64 nDeltas[] = {0, 4, 8, 0x10};

            for (qint64 nDelta : nDeltas) {
                if ((nOverlayOffset + nDelta + 64 <= nFileSize) &&
                    addCandidate(nOverlayOffset + nDelta, (nDelta == 0) ? 1 : 3, nDelta ? QString("overlay +0x%1").arg(nDelta, 0, 16) : QString("overlay start"), false)) {
                    nOverlayCandidates++;
                }
            }
        }
    } else {
        addRegion(0, nFileSize, QString("file"));
        addCandidate(0, 0, QString("start of file (not a PE file)"), false);
        result.listLog.append(QString("Not a PE file: only offset 0 is tried"));
    }

    result.bIsValid = true;
    result.listLog.append(QString("Candidates: %1 (high-entropy sections %2, entry point references %3, overlay %4)")
                              .arg(mapCandidates.count())
                              .arg(nSectionCandidates)
                              .arg(nEpCandidates)
                              .arg(nOverlayCandidates));

    // order: entry point references, then section/overlay starts, then the small deltas
    QList<CANDIDATE> listCandidates = mapCandidates.values();
    std::stable_sort(listCandidates.begin(), listCandidates.end(), [](const CANDIDATE &a, const CANDIDATE &b) { return a.nPriority < b.nPriority; });

    QElapsedTimer timerScan;
    timerScan.start();

    QList<BLOB> listBlobs;
    QSet<QByteArray> stSeen;  // algo + size + hash of the output
    qint32 nAttempts = 0;
    bool bStopped = false;
    static const ALGO algos[] = {ALGO_LZMA, ALGO_ZLIB, ALGO_NRV2B, ALGO_NRV2D, ALGO_NRV2E, ALGO_APLIB, ALGO_LZNT1, ALGO_DEFLATE};

    for (qint32 i = 0; (i < listCandidates.count()) && !bStopped; i++) {
        const CANDIDATE &candidate = listCandidates.at(i);

        // skip offsets that lie inside an already decoded stream
        bool bInside = false;

        for (const BLOB &blob : listBlobs) {
            if ((candidate.nOffset > blob.nOffset) && (candidate.nOffset < blob.nOffset + blob.nCompressedSize)) {
                bInside = true;
                break;
            }
        }

        if (bInside) {
            continue;
        }

        const quint8 *pInput = pFile + candidate.nOffset;
        qint64 nInputSize = qMin<qint64>(candidate.nEnd - candidate.nOffset, N_HELPER_MAX_INPUT);

        for (ALGO algo : algos) {
            if (!XBinary::isPdStructNotCanceled(pPdStruct)) {
                result.listLog.append(QString("Cancelled"));
                bStopped = true;
                break;
            }

            if (timerScan.elapsed() >= N_HELPER_SCAN_BUDGET_MS) {
                result.listLog.append(QString("Time budget of %1 s used up after %2 attempt(s); remaining candidates skipped").arg(N_HELPER_SCAN_BUDGET_MS / 1000).arg(nAttempts));
                bStopped = true;
                break;
            }

            DECODE_CONTEXT context = {};
            context.pPdStruct = pPdStruct;
            context.nBudgetMs = qMin<qint64>(N_HELPER_ATTEMPT_BUDGET_MS, N_HELPER_SCAN_BUDGET_MS - timerScan.elapsed());
            context.timer.start();

            QByteArray baOutput;
            qint64 nConsumed = 0;
            bool bClean = false;
            QString sVariant;
            nAttempts++;

            if (!_decode(algo, pInput, nInputSize, &baOutput, N_HELPER_MAX_OUTPUT, &nConsumed, &bClean, &sVariant, &context)) {
                continue;
            }

            if ((baOutput.size() < N_HELPER_MIN_OUTPUT) || (nConsumed <= 0)) {
                continue;
            }

            nConsumed = qMin<qint64>(nConsumed, nInputSize);

            double dStreamEntropy = _entropy(pInput, qMin<qint64>(nConsumed, 0x100000));
            double dOutputEntropy = _entropy((const quint8 *)baOutput.constData(), qMin<qint64>(baOutput.size(), 0x400000));
            bool bIsPE = false;
            bool bMZ = _looksLikeMZ(baOutput, &bIsPE);
            qint32 nCalls = 0;
            bool bCode = _looksLikeX86Code(baOutput, &nCalls);
            bool bEntropyDrop = (dOutputEntropy < 7.2) && (dOutputEntropy + 0.5 < dStreamEntropy) && (baOutput.size() > nConsumed);

            // plausible: something recognisable, or a clean stream that really expands into lower-entropy data
            if (!(bMZ || bCode || (bClean && bEntropyDrop))) {
                continue;
            }

            QByteArray baKey = QByteArray::number((int)algo) + ":" + QByteArray::number(baOutput.size()) + ":" + QByteArray::number(qHash(baOutput));

            if (stSeen.contains(baKey)) {
                continue;
            }

            stSeen.insert(baKey);

            qint32 nScore = 20;
            QStringList listDetails;

            if (bMZ) {
                nScore += bIsPE ? 45 : 35;
                listDetails.append(bIsPE ? QString("output is a PE image") : QString("output starts with MZ"));
            }

            if (bCode) {
                nScore += 25;
                listDetails.append(QString("x86/x64 code (%1 in-range calls)").arg(nCalls));
            }

            if (bClean) {
                nScore += 10;
            }

            if (dStreamEntropy > dOutputEntropy) {
                nScore += qMin<qint32>(15, (qint32)((dStreamEntropy - dOutputEntropy) * 5));
            }

            nScore += qMin<qint32>(10, (qint32)std::log2((double)baOutput.size() / 1024.0));

            if (candidate.bEpReference) {
                nScore += 5;
            }

            nScore = qBound(0, nScore, 100);

            listDetails.prepend(QString("%1; 0x%2 -> 0x%3 bytes; entropy %4 -> %5%6")
                                    .arg(sVariant)
                                    .arg(nConsumed, 0, 16)
                                    .arg(baOutput.size(), 0, 16)
                                    .arg(dStreamEntropy, 0, 'f', 2)
                                    .arg(dOutputEntropy, 0, 'f', 2)
                                    .arg(bClean ? QString() : QString("; stream not terminated")));
            listDetails.append(QString("found as: %1").arg(candidate.sReason));

            BLOB blob = {};
            blob.algo = algo;
            blob.nOffset = candidate.nOffset;
            blob.nCompressedSize = nConsumed;
            blob.baData = baOutput;
            blob.nScore = nScore;
            blob.sDetails = listDetails.join("; ");
            blob.sSection = candidate.sSection;
            listBlobs.append(blob);

            result.listLog.append(QString("%1 at 0x%2 (%3): 0x%4 -> 0x%5 bytes, score %6")
                                      .arg(algoToString(algo))
                                      .arg(candidate.nOffset, 0, 16)
                                      .arg(candidate.sSection)
                                      .arg(nConsumed, 0, 16)
                                      .arg(baOutput.size(), 0, 16)
                                      .arg(nScore));

            break;  // one algorithm per offset is enough
        }
    }

    std::stable_sort(listBlobs.begin(), listBlobs.end(), [](const BLOB &a, const BLOB &b) { return a.nScore > b.nScore; });

    while (listBlobs.count() > N_HELPER_MAX_BLOBS) {
        listBlobs.removeLast();
    }

    result.listBlobs = listBlobs;
    result.listLog.append(QString("%1 attempt(s) in %2 ms, %3 blob(s) kept").arg(nAttempts).arg(timerScan.elapsed()).arg(listBlobs.count()));

    return result;
}
