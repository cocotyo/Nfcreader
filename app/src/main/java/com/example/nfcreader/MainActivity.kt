package com.example.nfcreader

import android.app.PendingIntent
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.MifareClassic
import android.nfc.tech.MifareUltralight
import android.nfc.tech.Ndef
import android.nfc.tech.NfcA
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private var nfc: NfcAdapter? = null
    private lateinit var status: TextView
    private lateinit var output: TextView
    private var lastResult = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.status)
        output = findViewById(R.id.output)
        nfc = NfcAdapter.getDefaultAdapter(this)

        findViewById<Button>(R.id.btnCopy).setOnClickListener {
            if (lastResult.isEmpty()) {
                toast("Belum ada data. Scan kartu dulu.")
            } else {
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("Data NFC", lastResult))
                toast("Data disalin ke clipboard")
            }
        }
        findViewById<Button>(R.id.btnShare).setOnClickListener {
            if (lastResult.isEmpty()) {
                toast("Belum ada data. Scan kartu dulu.")
            } else {
                val i = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, lastResult)
                }
                startActivity(Intent.createChooser(i, "Bagikan data NFC"))
            }
        }

        if (nfc == null) status.text = "Perangkat ini tidak mendukung NFC"
        // Jika aplikasi dibuka oleh tag
        handleIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        val adapter = nfc ?: return
        if (!adapter.isEnabled) status.text = "NFC mati. Aktifkan di Pengaturan."
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )
        adapter.enableForegroundDispatch(this, pi, null, null)
    }

    override fun onPause() {
        super.onPause()
        nfc?.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val action = intent?.action ?: return
        if (action != NfcAdapter.ACTION_TAG_DISCOVERED &&
            action != NfcAdapter.ACTION_TECH_DISCOVERED &&
            action != NfcAdapter.ACTION_NDEF_DISCOVERED
        ) return
        val tag: Tag? = if (Build.VERSION.SDK_INT >= 33)
            intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag::class.java)
        else
            @Suppress("DEPRECATION") intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
        if (tag == null) return
        lastResult = readTag(tag)
        output.text = lastResult
        status.text = "Kartu terbaca. Tekan \"Salin data\" untuk menyalin."
    }

    private fun hex(b: ByteArray?, sep: String = " ") =
        b?.joinToString(sep) { "%02X".format(it) } ?: "-"

    private fun readTag(tag: Tag): String {
        val sb = StringBuilder()
        sb.appendLine("UID: ${hex(tag.id, ":")}")
        sb.appendLine("Teknologi: ${tag.techList.joinToString { it.substringAfterLast('.') }}")

        // NfcA (ATQA / SAK)
        NfcA.get(tag)?.let {
            sb.appendLine("ATQA: ${hex(it.atqa)}  SAK: %02X".format(it.sak))
        }

        // NDEF
        Ndef.get(tag)?.let { ndef ->
            sb.appendLine("\n[NDEF] tipe: ${ndef.type}, kapasitas: ${ndef.maxSize} byte")
            val msg = ndef.cachedNdefMessage
            if (msg == null) sb.appendLine("(tidak ada pesan NDEF)")
            msg?.records?.forEachIndexed { i, r ->
                sb.appendLine("Record ${i + 1}: ${describe(r)}")
            }
        }

        // MIFARE Classic (hanya sektor yang bisa dibuka dengan kunci default)
        MifareClassic.get(tag)?.let { mc ->
            sb.appendLine("\n[MIFARE Classic] ukuran: ${mc.size} byte, sektor: ${mc.sectorCount}")
            try {
                mc.connect()
                for (s in 0 until mc.sectorCount) {
                    val ok = mc.authenticateSectorWithKeyA(s, MifareClassic.KEY_DEFAULT) ||
                            mc.authenticateSectorWithKeyA(s, MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY) ||
                            mc.authenticateSectorWithKeyA(s, MifareClassic.KEY_NFC_FORUM)
                    if (!ok) { sb.appendLine("Sektor $s: terkunci (kunci tidak diketahui)"); continue }
                    val first = mc.sectorToBlock(s)
                    for (b in first until first + mc.getBlockCountInSector(s)) {
                        sb.appendLine("S$s B$b: ${hex(mc.readBlock(b))}")
                    }
                }
            } catch (e: Exception) {
                sb.appendLine("Gagal membaca: ${e.message}")
            } finally {
                try { mc.close() } catch (_: Exception) {}
            }
        }

        // MIFARE Ultralight / NTAG
        MifareUltralight.get(tag)?.let { mu ->
            sb.appendLine("\n[MIFARE Ultralight/NTAG]")
            try {
                mu.connect()
                var page = 0
                while (page < 40) {
                    val data = try { mu.readPages(page) } catch (_: Exception) { break }
                    for (p in 0 until 4) {
                        sb.appendLine("Page ${page + p}: ${hex(data.copyOfRange(p * 4, p * 4 + 4))}")
                    }
                    page += 4
                }
            } catch (e: Exception) {
                sb.appendLine("Gagal membaca: ${e.message}")
            } finally {
                try { mu.close() } catch (_: Exception) {}
            }
        }
        return sb.toString()
    }

    private fun describe(r: NdefRecord): String {
        r.toUri()?.let { return "URI -> $it" }
        if (r.tnf == NdefRecord.TNF_WELL_KNOWN && r.type.contentEquals(NdefRecord.RTD_TEXT)) {
            val p = r.payload
            if (p.isNotEmpty()) {
                val langLen = p[0].toInt() and 0x3F
                val utf16 = (p[0].toInt() and 0x80) != 0
                val cs = if (utf16) Charsets.UTF_16 else Charsets.UTF_8
                return "Teks -> " + String(p, 1 + langLen, p.size - 1 - langLen, cs)
            }
        }
        return "TNF=${r.tnf} tipe=${String(r.type)} payload=${hex(r.payload)}"
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
}
