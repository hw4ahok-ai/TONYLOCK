package com.tonylock.app

import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {

    private lateinit var passwordInput: EditText
    private lateinit var passwordConfirmInput: EditText
    private lateinit var statusText: TextView

    private var pendingMode: Mode? = null
    private var pendingInputUri: Uri? = null
    private var pendingOriginalName: String = "file"

    private enum class Mode { ENCRYPT, DECRYPT }

    private val openFileLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri == null) return@registerForActivityResult

            pendingInputUri = uri

            when (pendingMode) {
                Mode.ENCRYPT -> {
                    val original = getDisplayName(uri) ?: "file"
                    pendingOriginalName = original
                    createFileLauncher.launch("$original.tlock")
                }

                Mode.DECRYPT -> {
                    try {
                        pendingOriginalName = readOriginalName(uri)
                        createFileLauncher.launch(pendingOriginalName)
                    } catch (e: Exception) {
                        showStatus("Gagal membaca file TONYLOCK: ${e.message}")
                    }
                }

                null -> Unit
            }
        }

    private val createFileLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { outputUri ->

            val inputUri = pendingInputUri
            val mode = pendingMode

            if (outputUri == null || inputUri == null || mode == null) {
                showStatus("Dibatalkan.")
                return@registerForActivityResult
            }

            Thread {
                try {
                    when (mode) {
                        Mode.ENCRYPT -> encryptFile(inputUri, outputUri)
                        Mode.DECRYPT -> decryptFile(inputUri, outputUri)
                    }

                    runOnUiThread {
                        showStatus(
                            if (mode == Mode.ENCRYPT)
                                "Berhasil. File sudah dikunci."
                            else
                                "Berhasil. File sudah dibuka."
                        )
                    }

                } catch (e: Exception) {
                    runOnUiThread {
                        showStatus(
                            "Gagal: ${e.message ?: e.javaClass.simpleName}"
                        )
                    }
                }
            }.start()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        passwordInput = findViewById(R.id.passwordInput)
        passwordConfirmInput = findViewById(R.id.passwordConfirmInput)
        statusText = findViewById(R.id.statusText)

        findViewById<Button>(R.id.encryptButton).setOnClickListener {

            val p1 = passwordInput.text.toString()
            val p2 = passwordConfirmInput.text.toString()

            if (p1.length < 8) {
                showStatus("Password minimal 8 karakter.")
                return@setOnClickListener
            }

            if (p1 != p2) {
                showStatus("Password dan konfirmasi tidak sama.")
                return@setOnClickListener
            }

            pendingMode = Mode.ENCRYPT

            showStatus("Pilih file yang ingin dikunci.")

            openFileLauncher.launch(arrayOf("*/*"))
        }

        findViewById<Button>(R.id.decryptButton).setOnClickListener {

            val p1 = passwordInput.text.toString()

            if (p1.isEmpty()) {
                showStatus("Masukkan password terlebih dahulu.")
                return@setOnClickListener
            }

            pendingMode = Mode.DECRYPT

            showStatus("Pilih file .tlock yang ingin dibuka.")

            openFileLauncher.launch(arrayOf("*/*"))
        }
    }

    private fun encryptFile(inputUri: Uri, outputUri: Uri) {

        val password = passwordInput.text.toString().toCharArray()

        val salt = ByteArray(SALT_SIZE).also {
            SecureRandom().nextBytes(it)
        }

        val iv = ByteArray(IV_SIZE).also {
            SecureRandom().nextBytes(it)
        }

        val key = deriveKey(password, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")

        cipher.init(
            Cipher.ENCRYPT_MODE,
            key,
            GCMParameterSpec(TAG_BITS, iv)
        )

        val originalNameBytes =
            pendingOriginalName.toByteArray(Charsets.UTF_8)

        require(originalNameBytes.size <= 65535) {
            "Nama file terlalu panjang."
        }

        contentResolver.openInputStream(inputUri).use { rawInput ->

            requireNotNull(rawInput) {
                "Tidak bisa membuka file sumber."
            }

            contentResolver.openOutputStream(outputUri, "w").use { rawOutput ->

                requireNotNull(rawOutput) {
                    "Tidak bisa membuat file tujuan."
                }

                val out =
                    DataOutputStream(
                        BufferedOutputStream(rawOutput)
                    )

                out.write(MAGIC)

                out.writeByte(VERSION)

                out.writeInt(PBKDF2_ITERATIONS)

                out.writeByte(salt.size)
                out.write(salt)

                out.writeByte(iv.size)
                out.write(iv)

                out.writeShort(originalNameBytes.size)
                out.write(originalNameBytes)

                out.flush()

                CipherOutputStream(out, cipher).use { cipherOut ->

                    BufferedInputStream(rawInput).use { input ->

                        input.copyTo(
                            cipherOut,
                            BUFFER_SIZE
                        )
                    }
                }
            }
        }

        password.fill('\u0000')
    }

    private fun decryptFile(inputUri: Uri, outputUri: Uri) {

        val password =
            passwordInput.text.toString().toCharArray()

        contentResolver.openInputStream(inputUri).use { rawInput ->

            requireNotNull(rawInput) {
                "Tidak bisa membuka file sumber."
            }

            val input =
                DataInputStream(
                    BufferedInputStream(rawInput)
                )

            val header = readHeader(input)

            val key =
                deriveKey(
                    password,
                    header.salt,
                    header.iterations
                )

            val cipher =
                Cipher.getInstance("AES/GCM/NoPadding")

            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(
                    TAG_BITS,
                    header.iv
                )
            )

            contentResolver.openOutputStream(outputUri, "w").use { rawOutput ->

                requireNotNull(rawOutput) {
                    "Tidak bisa membuat file tujuan."
                }

                BufferedOutputStream(rawOutput).use { output ->

                    CipherInputStream(input, cipher).use { cipherInput ->

                        cipherInput.copyTo(
                            output,
                            BUFFER_SIZE
                        )
                    }
                }
            }
        }

        password.fill('\u0000')
    }

    private fun readOriginalName(uri: Uri): String {

        contentResolver.openInputStream(uri).use { rawInput ->

            requireNotNull(rawInput) {
                "Tidak bisa membuka file."
            }

            val input =
                DataInputStream(
                    BufferedInputStream(rawInput)
                )

            return readHeader(input).originalName
        }
    }

    private data class Header(
        val iterations: Int,
        val salt: ByteArray,
        val iv: ByteArray,
        val originalName: String
    )

    private fun readHeader(input: DataInputStream): Header {

        val magic = ByteArray(MAGIC.size)

        input.readFully(magic)

        require(magic.contentEquals(MAGIC)) {
            "Bukan file TONYLOCK."
        }

        val version =
            input.readUnsignedByte()

        require(version == VERSION) {
            "Versi file tidak didukung."
        }

        val iterations =
            input.readInt()

        require(iterations in 100_000..2_000_000) {
            "Header file tidak valid."
        }

        val saltLen =
            input.readUnsignedByte()

        require(saltLen in 8..64) {
            "Salt tidak valid."
        }

        val salt =
            ByteArray(saltLen)

        input.readFully(salt)

        val ivLen =
            input.readUnsignedByte()

        require(ivLen in 12..32) {
            "IV tidak valid."
        }

        val iv =
            ByteArray(ivLen)

        input.readFully(iv)

        val nameLen =
            input.readUnsignedShort()

        require(nameLen in 1..65535) {
            "Nama file tidak valid."
        }

        val nameBytes =
            ByteArray(nameLen)

        input.readFully(nameBytes)

        val originalName =
            nameBytes.toString(Charsets.UTF_8)

        return Header(
            iterations,
            salt,
            iv,
            originalName
        )
    }

    private fun deriveKey(
        password: CharArray,
        salt: ByteArray,
        iterations: Int = PBKDF2_ITERATIONS
    ): SecretKeySpec {

        val spec =
            PBEKeySpec(
                password,
                salt,
                iterations,
                KEY_BITS
            )

        val factory =
            SecretKeyFactory.getInstance(
                "PBKDF2WithHmacSHA256"
            )

        val encoded =
            factory.generateSecret(spec).encoded

        spec.clearPassword()

        return SecretKeySpec(
            encoded,
            "AES"
        )
    }

    private fun getDisplayName(uri: Uri): String? {

        contentResolver.query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null
        )?.use { cursor ->

            if (cursor.moveToFirst()) {

                val idx =
                    cursor.getColumnIndex(
                        OpenableColumns.DISPLAY_NAME
                    )

                if (idx >= 0)
                    return cursor.getString(idx)
            }
        }

        return null
    }

    private fun showStatus(message: String) {
        statusText.text = message
    }

    companion object {

        private val MAGIC =
            byteArrayOf(
                'T'.code.toByte(),
                'L'.code.toByte(),
                'O'.code.toByte(),
                'C'.code.toByte(),
                'K'.code.toByte()
            )

        private const val VERSION = 1

        private const val SALT_SIZE = 16

        private const val IV_SIZE = 12

        private const val TAG_BITS = 128

        private const val KEY_BITS = 256

        private const val PBKDF2_ITERATIONS = 310_000

        private const val BUFFER_SIZE =
            64 * 1024
    }
}
