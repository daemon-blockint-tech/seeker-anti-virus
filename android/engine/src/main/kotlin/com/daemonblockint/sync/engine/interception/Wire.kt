package com.daemonblockint.sync.engine.interception

/** Well-known Solana program ids and their risk-relevant traits. */
data class KnownProgram(val name: String, val sensitive: Boolean)

val KNOWN_PROGRAMS: Map<String, KnownProgram> = mapOf(
    "11111111111111111111111111111111" to KnownProgram("System Program", true),
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" to KnownProgram("SPL Token", true),
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" to KnownProgram("SPL Token-2022", true),
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL" to KnownProgram("Associated Token Account", false),
    "ComputeBudget111111111111111111111111111111" to KnownProgram("Compute Budget", false),
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr" to KnownProgram("Memo", false),
)

/** System Program instruction index for a lamport transfer. */
const val SYSTEM_TRANSFER_IX = 2

/** SPL Token `Approve` instruction index (delegation — drainer primitive). */
const val TOKEN_APPROVE_IX = 4

/** SPL Token `SetAuthority` instruction index. */
const val TOKEN_SET_AUTHORITY_IX = 6

private const val SYSTEM_PROGRAM = "11111111111111111111111111111111"
private val TOKEN_PROGRAMS = setOf(
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
)

const val BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

/** Encode bytes as a base58 string (Bitcoin/Solana alphabet). */
fun bytesToBase58(bytes: ByteArray): String {
    if (bytes.isEmpty()) return ""

    var zeros = 0
    while (zeros < bytes.size && bytes[zeros] == 0.toByte()) zeros++

    val digits = mutableListOf<Int>()
    for (i in zeros until bytes.size) {
        var carry = bytes[i].toInt() and 0xFF
        for (j in digits.indices) {
            carry += digits[j] shl 8
            digits[j] = carry % 58
            carry /= 58
        }
        while (carry > 0) {
            digits.add(carry % 58)
            carry /= 58
        }
    }

    val sb = StringBuilder()
    repeat(zeros) { sb.append('1') }
    for (i in digits.indices.reversed()) {
        sb.append(BASE58_ALPHABET[digits[i]])
    }
    return sb.toString()
}

/** Sequential byte reader with Solana shortvec (compact-u16) support. */
class ByteReader(private val bytes: ByteArray) {
    private var offset = 0

    val remaining: Int get() = bytes.size - offset

    fun u8(): Int {
        require(offset < bytes.size) { "unexpected end of buffer" }
        return bytes[offset++].toInt() and 0xFF
    }

    fun take(n: Int): ByteArray {
        require(offset + n <= bytes.size) { "unexpected end of buffer" }
        val slice = bytes.copyOfRange(offset, offset + n)
        offset += n
        return slice
    }

    /** Decode a shortvec-encoded length (compact-u16). */
    fun compactU16(): Int {
        var value = 0
        var shift = 0
        while (true) {
            val byte = u8()
            value = value or ((byte and 0x7f) shl shift)
            if ((byte and 0x80) == 0) break
            shift += 7
            require(shift <= 21) { "invalid compact-u16" }
        }
        return value and 0xFFFFFFFF.toInt()
    }
}

/** Read a little-endian u64 from 8 bytes as a Long. */
fun readU64LE(bytes: ByteArray): Long {
    var value = 0L
    for (i in 7 downTo 0) {
        value = (value shl 8) or (bytes[i].toLong() and 0xFF)
    }
    return value
}

/** Read a little-endian u32 from the first 4 bytes. */
fun readU32LE(bytes: ByteArray): Int =
    ((bytes[0].toInt() and 0xFF) or
        ((bytes[1].toInt() and 0xFF) shl 8) or
        ((bytes[2].toInt() and 0xFF) shl 16) or
        ((bytes[3].toInt() and 0xFF) shl 24)) and 0xFFFFFFFF.toInt()

/** Helper to convert hex string to byte array. */
internal fun hexToBytes(hex: String): ByteArray {
    val out = ByteArray(hex.length / 2)
    for (i in out.indices) {
        out[i] = hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
    return out
}

/** Helper to convert bytes to hex string. */
internal fun toHex(bytes: ByteArray): String =
    bytes.joinToString("") { it.toInt().and(0xFF).toString(16).padStart(2, '0') }

/** Check if a program id is the System Program. */
internal fun isSystemProgram(programId: String): Boolean = programId == SYSTEM_PROGRAM

/** Check if a program id is an SPL Token program. */
internal fun isTokenProgram(programId: String): Boolean = programId in TOKEN_PROGRAMS
