package com.v2ray.ang.core

import com.google.gson.JsonObject
import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

/**
 * Measures real download throughput of a single profile.
 *
 * A temporary Xray core instance is started with a loopback SOCKS inbound on a
 * random free port, then a test file is downloaded from Cloudflare through that
 * proxy. Profiles behind "type 2" whitelists (speed shaped) answer pings fine
 * but cannot sustain the download, which is exactly what this test detects.
 */
object WhitelistSpeedTester {

    private const val DOWNLOAD_TEST_URL = "https://speed.cloudflare.com/__down?bytes="
    private const val PROXY_START_TIMEOUT_MS = 5_000L
    private const val PROXY_START_POLL_MS = 100L
    private const val PROXY_WARMUP_MS = 700L
    private const val INTER_ATTEMPT_DELAY_MS = 500L

    data class Settings(
        val downloadSizeMb: Int,
        val downloadTimeoutSeconds: Int,
        val downloadAttempts: Int,
    )

    /**
     * Runs the download probe for one profile.
     *
     * @return pair of average speed in bytes per second (always >= 0 when any
     * full download (stable). Speed is never negative: even a failed probe
     * reports 0 so the UI can always show a number instead of a dash.
     */
    fun measureProfileSpeed(guid: String, settings: Settings): Pair<Long, Boolean> {
        val port = Utils.findRandomFreePort()
        var controller: CoreController? = null
        return try {
            val configResult = CoreConfigManager.getV2rayConfig4SpeedtestWithSocksInbound(guid, port)
            if (!configResult.status) {
                return Pair(0L, false)
            }

            controller = CoreNativeManager.newCoreController(NoOpCallback())
            controller.startLoop(configResult.content, 0)
            if (!waitForLocalProxy(port)) {
                LogUtil.e(AppConfig.TAG, "WhitelistSpeedTester: local proxy did not open on port $port")
                return Pair(0L, false)
            }
            Thread.sleep(PROXY_WARMUP_MS)

            runDownloadAttempts(port, settings)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "WhitelistSpeedTester: failed to measure profile $guid", e)
            Pair(0L, false)
        } finally {
            try {
                controller?.stopLoop()
            } catch (e: Exception) {
                LogUtil.w(AppConfig.TAG, "WhitelistSpeedTester: failed to stop core: ${e.message}")
            }
        }
    }

    /**
     * Downloads the test file [Settings.downloadAttempts] times and averages the speed.
     */
    private fun runDownloadAttempts(port: Int, settings: Settings): Pair<Long, Boolean> {
        val targetBytes = settings.downloadSizeMb.toLong() * 1024L * 1024L
        val timeoutMs = settings.downloadTimeoutSeconds.toLong() * 1000L
        val client = OkHttpClient.Builder()
            .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(AppConfig.LOOPBACK, port)))
            .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            .build()

        var totalBytes = 0L
        var totalElapsedMs = 0L
        var completedRuns = 0

        repeat(settings.downloadAttempts) { attempt ->
            val result = downloadOnce(client, targetBytes, timeoutMs)
            totalBytes += result.first
            totalElapsedMs += result.second
            if (result.first >= targetBytes) {
                completedRuns++
            }
            if (attempt < settings.downloadAttempts - 1 && result.first < targetBytes) {
                Thread.sleep(INTER_ATTEMPT_DELAY_MS)
            }
        }

        if (totalElapsedMs <= 0L || totalBytes <= 0L) {
            return Pair(0L, false)
        }
        // Stable only when every attempt carried the full test file: a shaped
        // ("type 2" whitelist) line trickles a few hundred KB and never finishes.
        return Pair(totalBytes * 1000L / totalElapsedMs, completedRuns >= settings.downloadAttempts)
    }

    /** @return pair of bytes read and elapsed milliseconds. */
    private fun downloadOnce(client: OkHttpClient, targetBytes: Long, timeoutMs: Long): Pair<Long, Long> {
        val request = Request.Builder()
            .url(DOWNLOAD_TEST_URL + targetBytes)
            .get()
            .header("Connection", "close")
            .build()

        val startedAt = System.currentTimeMillis()
        var bytesRead = 0L
        try {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return Pair(0L, System.currentTimeMillis() - startedAt)
                }
                val body = response.body ?: return Pair(0L, System.currentTimeMillis() - startedAt)
                val buffer = ByteArray(64 * 1024)
                body.byteStream().use { input ->
                    while (bytesRead < targetBytes) {
                        if (System.currentTimeMillis() - startedAt > timeoutMs) break
                        val limit = minOf(buffer.size.toLong(), targetBytes - bytesRead).toInt()
                        val read = input.read(buffer, 0, limit)
                        if (read == -1) break
                        bytesRead += read
                    }
                }
            }
        } catch (e: Exception) {
            LogUtil.d(AppConfig.TAG, "WhitelistSpeedTester: download interrupted after $bytesRead bytes: ${e.message}")
        }
        return Pair(bytesRead, maxOf(1L, System.currentTimeMillis() - startedAt))
    }

    private fun waitForLocalProxy(port: Int): Boolean {
        val deadline = System.currentTimeMillis() + PROXY_START_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            try {
                java.net.Socket().use { probe ->
                    probe.connect(java.net.InetSocketAddress(AppConfig.LOOPBACK, port), 300)
                }
                return true
            } catch (_: Exception) {
                Thread.sleep(PROXY_START_POLL_MS)
            }
        }
        return false
    }

    private class NoOpCallback : CoreCallbackHandler {
        override fun startup(): Long = 0
        override fun shutdown(): Long = 0
        override fun onEmitStatus(l: Long, s: String?): Long = 0
    }
}
