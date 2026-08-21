package com.v2ray.ang.service

import android.content.Context
import com.v2ray.ang.core.WhitelistSpeedTester
import com.v2ray.ang.dto.RealPingEvent
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.handler.SpeedtestManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.Executors

/**
 * Two-phase "whitelist" profile search.
 *
 * Phase 1: TCP-ping every profile in parallel to drop dead ones fast.
 * Phase 2: speed-probe the best candidates sequentially (one temp core at a
 * time), best ping first, until the target number of stable profiles is found.
 *
 * Profiles behind "type 2" whitelists answer pings but cannot sustain a
 * download, so only the download phase separates them from usable profiles.
 */
class WhitelistSearchWorkerService(
    private val context: Context,
    private val guids: List<String>,
    private val onEvent: (RealPingEvent) -> Unit = {}
) {
    private val job = SupervisorJob()
    private val dispatcher = Executors.newFixedThreadPool(WL_TCPING_PARALLELISM).asCoroutineDispatcher()
    private val scope = CoroutineScope(job + dispatcher + CoroutineName("WhitelistSearchWorker"))
    private val probeMutex = Mutex()

    fun start() {
        scope.launch {
            try {
                runSearch()
                if (job.isActive) onEvent(RealPingEvent.Finish("0"))
            } catch (_: CancellationException) {
                // cancelled, no finish event
            } catch (e: Exception) {
                if (job.isActive) onEvent(RealPingEvent.Finish(e.message ?: "error"))
            } finally {
                close()
            }
        }
    }

    fun cancel() {
        job.cancel()
    }

    private fun close() {
        try {
            dispatcher.close()
        } catch (_: Throwable) {
        }
    }

    private suspend fun runSearch() {
        val targetCount = SettingsManager.getWlTargetCount()
        val tcpingTimeoutMs = SettingsManager.getWlTcpingTimeoutMs()
        val probeSettings = WhitelistSpeedTester.Settings(
            downloadSizeMb = SettingsManager.getWlDownloadSizeMb(),
            downloadTimeoutSeconds = SettingsManager.getWlDownloadTimeoutSeconds(),
            downloadAttempts = SettingsManager.getWlDownloadAttempts(),
        )

        // Phase 1: TCP ping everything in parallel.
        onEvent(RealPingEvent.Progress("0 / ${guids.size}"))
        val pingResults = mutableMapOf<String, Long>()
        val jobs = guids.map { guid ->
            scope.launch {
                val ping = tcping(guid, tcpingTimeoutMs)
                synchronized(pingResults) {
                    pingResults[guid] = ping
                }
                MmkvManager.encodeServerTestDelayMillis(guid, ping)
                if (job.isActive) onEvent(RealPingEvent.Result(guid, ping))
            }
        }
        joinAll(*jobs.toTypedArray())
        if (!job.isActive) return

        // Phase 2: speed-probe the fastest responders, stop early once enough stable profiles found.
        val candidates = pingResults.filterValues { it >= 0L }
            .entries.sortedBy { it.value }
            .take(targetCount * CANDIDATE_POOL_MULTIPLIER)
            .map { it.key }
        var stableFound = 0

        for ((index, guid) in candidates.withIndex()) {
            if (!job.isActive || stableFound >= targetCount) break
            onEvent(RealPingEvent.Progress("${index + 1} / ${candidates.size}"))
            val (speed, stable) = probeMutex.withLock {
                if (!job.isActive) return
                WhitelistSpeedTester.measureProfileSpeed(guid, probeSettings)
            }
            // Keep the measured speed visible even for shaped profiles...
            MmkvManager.encodeServerTestSpeedBytesPerSec(guid, speed)
            if (stable) {
                stableFound++
            } else {
                // ...but mark them failed so the ping turns red and sorting by
                // test results sinks them below the usable profiles.
                MmkvManager.encodeServerTestDelayMillis(guid, -1L)
            }
            if (job.isActive) onEvent(RealPingEvent.SpeedResult(guid, speed))
        }
    }

    private fun tcping(guid: String, timeoutMs: Int): Long {
        val config = MmkvManager.decodeServerConfig(guid) ?: return -1L
        val server = config.server ?: return -1L
        val port = config.serverPort?.toIntOrNull() ?: return -1L
        return SpeedtestManager.socketConnectTime(server, port, timeoutMs)
    }

    companion object {
        private const val WL_TCPING_PARALLELISM = 5
        private const val CANDIDATE_POOL_MULTIPLIER = 2
    }
}
