package com.v2ray.ang.dto.entities

data class ServerAffiliationInfo(
    var testDelayMillis: Long = 0L,
    var testSpeedBytesPerSec: Long = 0L,
    var testSpeedStable: Boolean = false,
    /** Distinguishes "probed, got N bytes/sec" from "never speed-tested" (0). */
    var testSpeedPresent: Boolean = false,
)
