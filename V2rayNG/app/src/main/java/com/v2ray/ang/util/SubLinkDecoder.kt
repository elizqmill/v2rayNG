package com.v2ray.ang.util

import androidx.annotation.StringRes
import com.v2ray.ang.R
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.URLDecoder
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher

/**
 * Расшифровка/разворот ссылок-обёрток подписок в обычный HTTP(S) адрес:
 *
 *  - `happ://add/<url>` — открытая ссылка Happ;
 *  - `happ://crypt…` — зашифрованные контейнеры Happ, поколения crypt…crypt5;
 *  - `incy://add/<url>`, `incy://import/<url>` — ссылки INCY;
 *  - `v2raytun://import/<url>` — ссылки v2RayTun.
 *
 * Криптоподход воспроизводит эталонные реализации (ZapretKVN): RSA PKCS#1 для
 * crypt…crypt4, RSA + ChaCha20-Poly1305 с байтовыми перестановками для crypt5.
 */
object SubLinkDecoder {

    sealed class Result {
        /** Ссылка развёрнута в обычный URL подписки. */
        data class Success(val url: String) : Result()

        /** Это уже обычная HTTP(S) ссылка — расшифровывать нечего. */
        object AlreadyPlain : Result()

        /** Развернуть не удалось: формат не опознан или данные повреждены. */
        data class Failed(@StringRes val messageRes: Int) : Result()
    }

    private const val KEYS_RESOURCE = "/sublink/happ_keys.txt"

    private val CRYPT_SCHEMES = listOf(
        "happ://crypt5/",
        "happ://crypt4/",
        "happ://crypt3/",
        "happ://crypt2/",
        "happ://crypt/",
    )

    private val WRAPPED_PREFIXES = listOf(
        "happ://add/",
        "incy://add/",
        "incy://import/",
        "v2raytun://import/",
    )

    private val DEEP_LINK_SCHEMES = setOf("happ", "incy", "v2raytun")

    fun decode(raw: String): Result {
        val text = raw.trim()
        if (text.isEmpty()) return Result.Failed(R.string.sub_link_not_supported)

        val scheme = text.substringBefore("://", missingDelimiterValue = "").lowercase()
        if (scheme == "http" || scheme == "https") return Result.AlreadyPlain

        if (isCryptLink(text)) {
            return try {
                val inner = unwrap(HappCrypt.decrypt(text).trim())
                if (isHttpUrl(inner)) Result.Success(inner)
                else Result.Failed(R.string.sub_link_no_url_inside)
            } catch (_: Exception) {
                Result.Failed(R.string.sub_link_decrypt_failed)
            }
        }

        if (scheme in DEEP_LINK_SCHEMES) {
            val body = text.substringAfter("://", missingDelimiterValue = "")
            if (body.substringBefore('?').lowercase().trimStart('/').startsWith("crypt")) {
                // Зашифрованные proprietary deep links других клиентов не поддерживаются.
                return Result.Failed(R.string.sub_link_not_supported)
            }
            var candidate = queryParameter(text, "url") ?: queryParameter(text, "data") ?: ""
            if (candidate.isEmpty()) {
                for (prefix in WRAPPED_PREFIXES) {
                    if (text.lowercase().startsWith(prefix)) {
                        candidate = urlDecode(text.substring(prefix.length).substringBefore('#')).trim()
                        break
                    }
                }
            }
            if (candidate.isNotEmpty()) {
                val decoded = unwrap(candidate)
                if (isHttpUrl(decoded)) return Result.Success(decoded)
                return Result.Failed(R.string.sub_link_no_url_inside)
            }
        }

        return Result.Failed(R.string.sub_link_not_supported)
    }

    private fun isCryptLink(value: String): Boolean =
        CRYPT_SCHEMES.any { value.trim().lowercase().startsWith(it) }

    private fun isHttpUrl(value: String): Boolean {
        val scheme = value.substringBefore("://", missingDelimiterValue = "").lowercase()
        return (scheme == "http" || scheme == "https") &&
            value.substringAfter("://").substringBefore('/').substringBefore('?').isNotBlank()
    }

    private fun queryParameter(url: String, name: String): String? {
        val query = url.substringAfter('?', missingDelimiterValue = "").substringBefore('#')
        if (query.isEmpty()) return null
        return query.split('&')
            .firstOrNull { it.substringBefore('=').equals(name, ignoreCase = true) }
            ?.substringAfter('=', missingDelimiterValue = "")
            ?.takeIf { it.isNotEmpty() }
            ?.let(::urlDecode)
    }

    private fun urlDecode(value: String): String = runCatching {
        URLDecoder.decode(value, Charsets.UTF_8.name())
    }.getOrDefault(value)

    /** Клиенты оборачивают адрес подписки в base64; открытый URL возвращается как есть. */
    private fun unwrap(value: String): String {
        if (isHttpUrl(value)) return value
        val compact = value.filterNot(Char::isWhitespace)
        if (compact.isEmpty() || !Regex("[A-Za-z0-9_+/=-]+").matches(compact)) return value
        return runCatching {
            val trimmed = compact.trimEnd('=')
            android.util.Base64.decode(
                trimmed + "=".repeat((4 - trimmed.length % 4) % 4),
                android.util.Base64.DEFAULT,
            ).toString(Charsets.UTF_8).trim()
        }.getOrDefault(value)
    }

    //region happ://crypt*

    private object HappCrypt {

        private const val CRYPT5_NONCE_SIZE = 12
        private const val CRYPT5_SALT_SIZE = 8
        private const val CRYPT5_SALT_OFFSET = 14
        private const val MARKER_SIZE = 4

        private class DecryptException(message: String, cause: Throwable? = null) :
            Exception(message, cause)

        private data class KeyTable(
            val generations: Map<Int, String>,
            val crypt5: Map<String, String>,
        )

        private val keys: KeyTable by lazy(::loadKeys)

        fun decrypt(value: String): String {
            val text = value.trim()
            val lowered = text.lowercase()
            for ((index, prefix) in CRYPT_SCHEMES.withIndex()) {
                if (!lowered.startsWith(prefix)) continue
                val payload = text.substring(prefix.length).trim()
                if (payload.isEmpty()) {
                    throw DecryptException("empty")
                }
                // Поколение = номер формата: crypt->0 ... crypt5->4. Индекс 0
                // списка и есть crypt5, остальные идут по убыванию поколения.
                return if (index == 0) decryptCrypt5(payload) else decryptCrypt1to4(payload, 4 - index)
            }
            throw DecryptException("not crypt")
        }

        private fun decryptCrypt1to4(payload: String, generation: Int): String {
            val key = loadKey(
                keys.generations[generation]
                    ?: throw DecryptException("no key"),
            )
            val ciphertext = decodeLooseBase64(payload)
            val blockSize = key.modulus.bitLength() / 8
            if (ciphertext.isEmpty() || ciphertext.size % blockSize != 0) {
                throw DecryptException("bad length")
            }
            val plaintext = ByteArrayOutputStream()
            var offset = 0
            while (offset < ciphertext.size) {
                val block = ciphertext.copyOfRange(offset, offset + blockSize)
                plaintext.write(
                    runCatching { rsaDecrypt(key, block) }.getOrElse {
                        throw DecryptException("unknown key", it)
                    },
                )
                offset += blockSize
            }
            return decodeText(plaintext.toByteArray())
        }

        private fun decryptCrypt5(payload: String): String {
            val swapped = swapBlockHalves(latin1Bytes(payload))
            if (swapped.size < MARKER_SIZE * 2 + CRYPT5_NONCE_SIZE) {
                throw DecryptException("too short")
            }
            val marker = String(
                swapped.copyOf(MARKER_SIZE) + swapped.copyOfRange(swapped.size - MARKER_SIZE, swapped.size),
                Charsets.ISO_8859_1,
            )
            val encodedKey = keys.crypt5[marker]
                ?: throw DecryptException("unknown marker")
            val key = loadKey(encodedKey)
            val body = swapped.copyOfRange(MARKER_SIZE, swapped.size - MARKER_SIZE)

            val saltedFirst = !isDigit(body, CRYPT5_NONCE_SIZE)
            var firstError: Exception? = null
            for (salted in listOf(saltedFirst, !saltedFirst)) {
                try {
                    return decryptCrypt5Body(body, key, salted)
                } catch (error: Exception) {
                    if (firstError == null) firstError = error
                }
            }
            throw DecryptException("crypt5 failed", firstError)
        }

        private fun decryptCrypt5Body(body: ByteArray, key: RSAPrivateKey, salted: Boolean): String {
            val nonce = body.copyOf(CRYPT5_NONCE_SIZE)
            val salt: ByteArray
            val cursor: Int
            if (salted) {
                if (body.size < CRYPT5_SALT_OFFSET + CRYPT5_SALT_SIZE) {
                    throw DecryptException("truncated")
                }
                salt = body.copyOfRange(CRYPT5_SALT_OFFSET, CRYPT5_SALT_OFFSET + CRYPT5_SALT_SIZE)
                cursor = CRYPT5_SALT_OFFSET + CRYPT5_SALT_SIZE
            } else {
                salt = ByteArray(0)
                cursor = CRYPT5_NONCE_SIZE
            }

            var lengthEnd = cursor
            while (isDigit(body, lengthEnd)) lengthEnd++
            if (lengthEnd == cursor) throw DecryptException("no length")
            val segmentLength = String(body.copyOfRange(cursor, lengthEnd), Charsets.ISO_8859_1)
                .toIntOrNull()
                ?: throw DecryptException("no length")

            val packed = body.copyOfRange(lengthEnd, body.size)
            if (packed.isEmpty() || segmentLength > packed.size - 1) {
                throw DecryptException("truncated")
            }
            val segment = packed.copyOfRange(1, 1 + segmentLength)
            val rsaCiphertext = packed.copyOfRange(1 + segmentLength, packed.size)

            var chachaKey = decodeLooseBase64(
                String(
                    swapPairs(rsaDecrypt(key, decodeLooseBase64(latin1String(rsaCiphertext)))),
                    Charsets.ISO_8859_1,
                ),
            )
            if (chachaKey.size != ChaCha20Poly1305.KEY_SIZE) {
                throw DecryptException("bad chacha key")
            }
            if (salt.isNotEmpty()) {
                chachaKey = ByteArray(chachaKey.size) { index ->
                    (chachaKey[index].toInt() xor salt[index % salt.size].toInt()).toByte()
                }
            }

            val opened = try {
                ChaCha20Poly1305.decrypt(chachaKey, nonce, decodeLooseBase64(latin1String(segment)))
            } catch (_: ChaCha20Poly1305.AuthenticationException) {
                throw DecryptException("auth failed")
            }
            return decodeText(decodeLooseBase64(latin1String(swapPairs(opened))))
        }

        private fun swapPairs(data: ByteArray): ByteArray {
            val buffer = data.copyOf()
            var index = 0
            while (index < buffer.size - 1) {
                val first = buffer[index]
                buffer[index] = buffer[index + 1]
                buffer[index + 1] = first
                index += 2
            }
            return buffer
        }

        private fun swapBlockHalves(data: ByteArray): ByteArray {
            val buffer = data.copyOf()
            var index = 0
            val end = buffer.size - buffer.size % 4
            while (index < end) {
                val first = buffer[index]
                val second = buffer[index + 1]
                buffer[index] = buffer[index + 2]
                buffer[index + 1] = buffer[index + 3]
                buffer[index + 2] = first
                buffer[index + 3] = second
                index += 4
            }
            return buffer
        }

        private fun isDigit(data: ByteArray, index: Int): Boolean =
            index < data.size && data[index] >= 48 && data[index] <= 57

        private fun rsaDecrypt(key: RSAPrivateKey, data: ByteArray): ByteArray =
            Cipher.getInstance("RSA/ECB/PKCS1Padding").run {
                init(Cipher.DECRYPT_MODE, key)
                doFinal(data)
            }

        private fun loadKey(encoded: String): RSAPrivateKey = runCatching {
            KeyFactory.getInstance("RSA")
                .generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(encoded)))
                as RSAPrivateKey
        }.getOrElse { throw DecryptException("broken key", it) }

        private fun decodeLooseBase64(value: String): ByteArray {
            val compact = value.filterNot(Char::isWhitespace)
                .replace('-', '+')
                .replace('_', '/')
                .trimEnd('=')
            val padded = compact + "=".repeat((4 - compact.length % 4) % 4)
            return runCatching { Base64.getDecoder().decode(padded) }.getOrElse {
                throw DecryptException("bad base64", it)
            }
        }

        private fun latin1Bytes(value: String): ByteArray {
            val buffer = ByteArray(value.length)
            var size = 0
            for (character in value) {
                if (character.code <= 0xff) buffer[size++] = character.code.toByte()
            }
            return buffer.copyOf(size)
        }

        private fun latin1String(data: ByteArray): String = String(data, Charsets.ISO_8859_1)

        private fun decodeText(data: ByteArray): String {
            val text = String(data, Charsets.UTF_8)
            if (text.contains('\uFFFD')) throw DecryptException("not text")
            return text.trim()
        }

        private fun loadKeys(): KeyTable {
            val stream = HappCrypt::class.java.getResourceAsStream(KEYS_RESOURCE)
                ?: throw DecryptException("keys missing")
            val generations = linkedMapOf<Int, String>()
            val crypt5 = linkedMapOf<String, String>()
            stream.bufferedReader(Charsets.UTF_8).useLines { lines ->
                lines.forEach { line ->
                    val trimmed = line.trim()
                    if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
                    val parts = trimmed.split(':', limit = 3)
                    if (parts.size != 3) return@forEach
                    when (parts[0]) {
                        "gen" -> parts[1].toIntOrNull()?.let { generations[it] = parts[2] }
                        "crypt5" -> crypt5[parts[1]] = parts[2]
                    }
                }
            }
            return KeyTable(generations, crypt5)
        }
    }

    //endregion

    /**
     * AEAD ChaCha20-Poly1305 по RFC 8439. Платформенный javax.crypto умеет этот
     * алгоритм только с API 28, поэтому считается здесь; данные короткие.
     */
    private object ChaCha20Poly1305 {

        const val KEY_SIZE = 32
        const val NONCE_SIZE = 12
        private const val TAG_SIZE = 16

        private val TWO: BigInteger = BigInteger.valueOf(2)
        private val POLY1305_PRIME: BigInteger = TWO.pow(130).subtract(BigInteger.valueOf(5))
        private val POLY1305_CLAMP: BigInteger =
            BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16)
        private val TAG_MODULUS: BigInteger = TWO.pow(128)

        class AuthenticationException : Exception("Poly1305 tag mismatch")

        fun decrypt(key: ByteArray, nonce: ByteArray, ciphertextWithTag: ByteArray): ByteArray {
            require(key.size == KEY_SIZE)
            require(nonce.size == NONCE_SIZE)
            if (ciphertextWithTag.size < TAG_SIZE) throw AuthenticationException()
            val ciphertext = ciphertextWithTag.copyOf(ciphertextWithTag.size - TAG_SIZE)
            val tag = ciphertextWithTag.copyOfRange(ciphertextWithTag.size - TAG_SIZE, ciphertextWithTag.size)
            val macKey = chacha20Block(key, nonce, counter = 0).copyOf(KEY_SIZE)
            val expected = poly1305(macKey, macData(ciphertext))
            if (!MessageDigest.isEqual(expected, tag)) throw AuthenticationException()
            return chacha20(key, nonce, ciphertext, initialCounter = 1)
        }

        private fun chacha20(key: ByteArray, nonce: ByteArray, data: ByteArray, initialCounter: Int): ByteArray {
            val output = ByteArray(data.size)
            var offset = 0
            var counter = initialCounter
            while (offset < data.size) {
                val block = chacha20Block(key, nonce, counter)
                val length = minOf(64, data.size - offset)
                for (index in 0 until length) {
                    output[offset + index] = (data[offset + index].toInt() xor block[index].toInt()).toByte()
                }
                offset += length
                counter++
            }
            return output
        }

        private fun chacha20Block(key: ByteArray, nonce: ByteArray, counter: Int): ByteArray {
            val state = IntArray(16)
            state[0] = 0x61707865
            state[1] = 0x3320646e
            state[2] = 0x79622d32
            state[3] = 0x6b206574
            for (index in 0 until 8) state[4 + index] = readLittleEndianInt(key, index * 4)
            state[12] = counter
            for (index in 0 until 3) state[13 + index] = readLittleEndianInt(nonce, index * 4)

            val working = state.copyOf()
            repeat(10) {
                quarterRound(working, 0, 4, 8, 12)
                quarterRound(working, 1, 5, 9, 13)
                quarterRound(working, 2, 6, 10, 14)
                quarterRound(working, 3, 7, 11, 15)
                quarterRound(working, 0, 5, 10, 15)
                quarterRound(working, 1, 6, 11, 12)
                quarterRound(working, 2, 7, 8, 13)
                quarterRound(working, 3, 4, 9, 14)
            }

            val block = ByteArray(64)
            for (index in 0 until 16) {
                writeLittleEndianInt(block, index * 4, working[index] + state[index])
            }
            return block
        }

        private fun quarterRound(state: IntArray, a: Int, b: Int, c: Int, d: Int) {
            state[a] += state[b]
            state[d] = Integer.rotateLeft(state[d] xor state[a], 16)
            state[c] += state[d]
            state[b] = Integer.rotateLeft(state[b] xor state[c], 12)
            state[a] += state[b]
            state[d] = Integer.rotateLeft(state[d] xor state[a], 8)
            state[c] += state[d]
            state[b] = Integer.rotateLeft(state[b] xor state[c], 7)
        }

        private fun macData(ciphertext: ByteArray): ByteArray {
            val output = ByteArray(padded(ciphertext.size) + 16)
            ciphertext.copyInto(output, 0)
            writeLittleEndianLong(output, padded(ciphertext.size), ciphertext.size.toLong())
            return output
        }

        private fun padded(size: Int): Int = size + ((16 - size % 16) % 16)

        private fun poly1305(macKey: ByteArray, message: ByteArray): ByteArray {
            val r = littleEndianNumber(macKey.copyOf(16)).and(POLY1305_CLAMP)
            val s = littleEndianNumber(macKey.copyOfRange(16, 32))
            var accumulator = BigInteger.ZERO
            var offset = 0
            while (offset < message.size) {
                val length = minOf(16, message.size - offset)
                val chunk = message.copyOfRange(offset, offset + length)
                val block = littleEndianNumber(chunk).add(TWO.pow(8 * length))
                accumulator = accumulator.add(block).multiply(r).mod(POLY1305_PRIME)
                offset += length
            }
            val tag = accumulator.add(s).mod(TAG_MODULUS)
            val output = ByteArray(TAG_SIZE)
            val bytes = tag.toByteArray()
            var index = 0
            for (position in bytes.indices.reversed()) {
                if (index >= TAG_SIZE) break
                output[index++] = bytes[position]
            }
            return output
        }

        private fun littleEndianNumber(data: ByteArray): BigInteger {
            val reversed = ByteArray(data.size + 1)
            for (index in data.indices) reversed[data.size - index] = data[index]
            return BigInteger(reversed)
        }

        private fun readLittleEndianInt(data: ByteArray, offset: Int): Int =
            (data[offset].toInt() and 0xff) or
                ((data[offset + 1].toInt() and 0xff) shl 8) or
                ((data[offset + 2].toInt() and 0xff) shl 16) or
                ((data[offset + 3].toInt() and 0xff) shl 24)

        private fun writeLittleEndianInt(data: ByteArray, offset: Int, value: Int) {
            data[offset] = (value and 0xff).toByte()
            data[offset + 1] = ((value ushr 8) and 0xff).toByte()
            data[offset + 2] = ((value ushr 16) and 0xff).toByte()
            data[offset + 3] = ((value ushr 24) and 0xff).toByte()
        }

        private fun writeLittleEndianLong(data: ByteArray, offset: Int, value: Long) {
            for (index in 0 until 8) {
                data[offset + index] = ((value ushr (8 * index)) and 0xff).toByte()
            }
        }
    }
}
