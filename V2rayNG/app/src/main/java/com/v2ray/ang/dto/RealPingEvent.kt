package com.v2ray.ang.dto

sealed class RealPingEvent {

    /** Periodic progress update while the batch is still running. */
    data class Progress(val text: String) : RealPingEvent()

    /** A single server result is available. */
    data class Result(val guid: String, val delayMillis: Long) : RealPingEvent()

    /** A single server download-speed result is available (bytes per second, -1 on probe failure). */
    data class SpeedResult(val guid: String, val speedBytesPerSec: Long, val stable: Boolean) : RealPingEvent()

    /** The entire batch has finished or been cancelled. */
    data class Finish(val status: String) : RealPingEvent()
}
