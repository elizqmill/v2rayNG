package com.v2ray.ang.service

import android.content.Context
import com.v2ray.ang.core.WhitelistSpeedTester
import com.v2ray.ang.dto.RealPingEvent
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
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
 * Phase 1: real ping every profile in parallel (full HTTP delay through a
 * temporary core, same as the regular delay test) to drop dead ones fast.
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
    private val dispatcher = Executors.newFixedThreadPool(SettingsManager.getRealPingConcurrency())
        .asCoroutineDispatcher()
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
        val probeSettings = WhitelistSpeedTester.Settings(
            downloadSizeMb = SettingsManager.getWlDownloadSizeMb(),
            downloadTimeoutSeconds = SettingsManager.getWlDownloadTimeoutSeconds(),
            downloadAttempts = SettingsManager.getWlDownloadAttempts(),
        )

        // Phase 1: real ping. Profiles that already carry a measured delay
        // (e.g. from a previous regular delay test) are reused as-is; only the
        // unmeasured ones are probed now.
        val pingResults = HashMap<String, Long>()
        val toPing = ArrayList<String>()
        for (guid in guids) {
            val existing = MmkvManager.decodeServerAffiliationInfo(guid)?.testDelayMillis ?: 0L
            if (existing == 0L) toPing.add(guid) else pingResults[guid] = existing
        }

        if (toPing.isNotEmpty()) {
            onEvent(RealPingEvent.Progress("ping 0/${toPing.size}"))
            val done = java.util.concurrent.atomic.AtomicInteger(0)
            val jobs = toPing.map { guid ->
                scope.launch {
                    val ping = RealPingMeasure.measure(guid)
                    synchronized(pingResults) {
                        pingResults[guid] = ping
                    }
                    MmkvManager.encodeServerTestDelayMillis(guid, ping)
                    if (job.isActive) {
                        onEvent(RealPingEvent.Result(guid, ping))
                        val n = done.incrementAndGet()
                        onEvent(RealPingEvent.Progress("ping $n/${toPing.size}"))
                    }
                }
            }
            joinAll(*jobs.toTypedArray())
        }
        if (!job.isActive) return

        // Phase 2: speed-probe every responsive profile, best ping first.
        // No early exit: leaving profiles unlabeled made it impossible to tell
        // whether they were ever speed-checked.
        val candidates = pingResults.filterValues { it >= 0L }
            .entries.sortedBy { it.value }
            .map { it.key }

        for ((index, guid) in candidates.withIndex()) {
            if (!job.isActive) break
            onEvent(RealPingEvent.Progress("speed ${index + 1}/${candidates.size}"))
            val (speed, stable) = probeMutex.withLock {
                if (!job.isActive) return
                WhitelistSpeedTester.measureProfileSpeed(guid, probeSettings)
            }
            // The measured ping stays untouched: a shaped profile keeps its green
            // delay numbers and is flagged only through its speed result.
            MmkvManager.encodeServerTestSpeedBytesPerSec(guid, speed, stable)
            if (job.isActive) onEvent(RealPingEvent.SpeedResult(guid, speed, stable))
        }
    }

    companion object
}
