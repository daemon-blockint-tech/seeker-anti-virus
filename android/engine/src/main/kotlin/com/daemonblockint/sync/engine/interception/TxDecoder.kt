package com.daemonblockint.sync.engine.interception

import com.daemonblockint.sync.engine.BehaviorEvent
import com.daemonblockint.sync.engine.ScanTarget

data class DecodedInstruction(
    val programId: String,
    val programName: String?,
    val accounts: List<String>,
    val dataHex: String,
    val dataLength: Int,
)

data class DecodedTransaction(
    val version: String, // "legacy" or version number as string
    val feePayer: String,
    val accountKeys: List<String>,
    val instructions: List<DecodedInstruction>,
)

/**
 * Decode a Solana transaction message (legacy or v0) into a normalized
 * DecodedTransaction. Address-table lookups in v0 messages are noted
 * but not resolved (they require an RPC round-trip).
 */
fun decodeMessage(message: ByteArray): DecodedTransaction {
    val r = ByteReader(message)

    var version: String = "legacy"
    var first = r.u8()
    if ((first and 0x80) != 0) {
        version = (first and 0x7f).toString()
        first = r.u8() // numRequiredSignatures of the versioned message
    }
    // first === numRequiredSignatures; skip the two readonly-count header bytes.
    r.u8()
    r.u8()

    val accountCount = r.compactU16()
    val accountKeys = mutableListOf<String>()
    for (i in 0 until accountCount) {
        accountKeys.add(bytesToBase58(r.take(32)))
    }

    r.take(32) // recent blockhash

    val ixCount = r.compactU16()
    val instructions = mutableListOf<DecodedInstruction>()
    for (i in 0 until ixCount) {
        val programIdIndex = r.u8()
        val acctCount = r.compactU16()
        val acctIndexes = mutableListOf<Int>()
        for (j in 0 until acctCount) acctIndexes.add(r.u8())
        val dataLen = r.compactU16()
        val data = r.take(dataLen)

        val programId = accountKeys.getOrNull(programIdIndex) ?: "#$programIdIndex"
        instructions.add(
            DecodedInstruction(
                programId = programId,
                programName = KNOWN_PROGRAMS[programId]?.name,
                accounts = acctIndexes.map { idx -> accountKeys.getOrNull(idx) ?: "#$idx" },
                dataHex = toHex(data),
                dataLength = data.size,
            ),
        )
    }

    return DecodedTransaction(
        version = version,
        feePayer = accountKeys.getOrElse(0) { "unknown" },
        accountKeys = accountKeys,
        instructions = instructions,
    )
}

/**
 * Decode a full serialized transaction (signature vector + message). Falls back
 * to treating the input as a bare message if no signature vector is present.
 */
fun decodeTransaction(tx: ByteArray): DecodedTransaction {
    val r = ByteReader(tx)
    val sigCount = r.compactU16()
    // A signature vector is 64 bytes each; if it doesn't fit, this is a bare message.
    if (sigCount > 0 && r.remaining >= sigCount * 64) {
        r.take(sigCount * 64)
        return decodeMessage(tx.copyOfRange(tx.size - r.remaining, tx.size))
    }
    return decodeMessage(tx)
}

/**
 * Turn a decoded transaction into a ScanTarget the engine can screen:
 * a text summary (for signature/YARA matching), program-id indicators, and
 * crypto-transaction BehaviorEvents (for the behavioral scanner).
 */
fun transactionToScanTarget(tx: DecodedTransaction, id: String? = null): ScanTarget {
    val events = mutableListOf<BehaviorEvent>()
    val summaryLines = mutableListOf("feePayer ${tx.feePayer}", "version ${tx.version}")

    for (ix in tx.instructions) {
        val label = ix.programName ?: ix.programId
        summaryLines.add("program $label data=${ix.dataHex.take(32)}")

        // System transfer: instruction index (u32 LE) === 2, then u64 LE lamports.
        if (isSystemProgram(ix.programId) && ix.dataLength >= 12) {
            val data = hexToBytes(ix.dataHex)
            if (readU32LE(data) == SYSTEM_TRANSFER_IX) {
                val lamports = readU64LE(data.copyOfRange(4, 12))
                val dest = ix.accounts.getOrElse(1) { "unknown" }
                summaryLines.add("transfer $lamports lamports -> $dest")
                events.add(
                    BehaviorEvent(
                        type = BehaviorEvent.Type.CRYPTO_TRANSACTION,
                        timestamp = System.currentTimeMillis(),
                        amountLamports = lamports,
                        targetAddress = dest,
                        programId = ix.programId,
                    ),
                )
            }
        }

        // SPL Token delegation / authority change — classic drainer primitives.
        if (isTokenProgram(ix.programId) && ix.dataLength >= 1) {
            val op = hexToBytes(ix.dataHex)[0].toInt() and 0xFF
            if (op == TOKEN_APPROVE_IX) summaryLines.add("token approve (delegation)")
            if (op == TOKEN_SET_AUTHORITY_IX) summaryLines.add("token set_authority")
            events.add(
                BehaviorEvent(
                    type = BehaviorEvent.Type.CRYPTO_TRANSACTION,
                    timestamp = System.currentTimeMillis(),
                    programId = ix.programId,
                ),
            )
        }
    }

    return ScanTarget(
        id = id ?: tx.feePayer,
        kind = ScanTarget.Kind.TRANSACTION,
        label = "tx by ${tx.feePayer.take(8)}…",
        text = summaryLines.joinToString("\n"),
        events = events,
    )
}
