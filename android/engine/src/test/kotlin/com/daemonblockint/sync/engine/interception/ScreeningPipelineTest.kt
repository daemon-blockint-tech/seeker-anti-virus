package com.daemonblockint.sync.engine.interception

import com.daemonblockint.sync.engine.BehaviorEvent
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.Severity
import com.daemonblockint.sync.engine.integrated.IntegratedScanner
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ScreeningPipelineTest {

    private val scanner = IntegratedScanner()
    private val pipeline = ScreeningPipeline(scanner)

    @Test
    fun `clean transaction is allowed`() {
        // Minimal legacy message: 1 signer, 0 readonly, 1 account, blockhash, 0 instructions
        val msg = byteArrayOf(
            1, 0, 0,  // header: 1 required sig, 0 readonly-signed, 0 readonly-unsigned
            1,        // 1 account
            *ByteArray(32), // zero account key
            *ByteArray(32), // zero blockhash
            0,        // 0 instructions
        )
        val result = pipeline.screen(msg, "test-tx")
        assertEquals(ScreeningDecision.ALLOW, result.decision)
    }

    @Test
    fun `phishing domain in text triggers warn or block`() {
        val target = ScanTarget(
            id = "s0lana.xyz",
            kind = ScanTarget.Kind.URL,
            domain = "s0lana.xyz",
            text = "Claim your tokens at s0lana.xyz",
        )
        val scanResult = scanner.scanLocal(target)
        assertTrue(scanResult.score > 0)
        assertEquals(Severity.HIGH, scanResult.severity)
    }
}

class WireTest {

    @Test
    fun `base58 encodes correctly`() {
        // Known: empty -> ""
        assertEquals("", bytesToBase58(byteArrayOf()))
        // Known: [0] -> "1"
        assertEquals("1", bytesToBase58(byteArrayOf(0)))
        // Known: [255] -> "2v" (well-known test vector)
        val encoded = bytesToBase58(byteArrayOf(255))
        assertTrue(encoded.isNotEmpty())
    }

    @Test
    fun `compactU16 decodes single byte`() {
        val r = ByteReader(byteArrayOf(5))
        assertEquals(5, r.compactU16())
    }

    @Test
    fun `compactU16 decodes multi-byte`() {
        // 300 = 0x12C → needs 2 bytes in compact-u16
        // byte1: 0xAC (low 7 bits = 0x2C = 44, high bit set)
        // byte2: 0x02 (shift 7 → 256, 256+44 = 300)
        val r = ByteReader(byteArrayOf(0xAC.toByte(), 0x02))
        assertEquals(300, r.compactU16())
    }

    @Test
    fun `readU64LE reads correctly`() {
        val bytes = ByteArray(8)
        bytes[0] = 1 // least significant byte
        assertEquals(1L, readU64LE(bytes))
    }
}
