package com.v2ray.ang.dto.entities

data class SubscriptionItem(
    var remarks: String = "",
    var url: String = "",
    var enabled: Boolean = true,
    val addedTime: Long = System.currentTimeMillis(),
    var lastUpdated: Long = -1,
    var autoUpdate: Boolean = false,
    var updateInterval: Long = 1440, // in minutes, default to 24 hours
    var prevProfile: String? = null,
    var nextProfile: String? = null,
    var filter: String? = null,
    var allowInsecureUrl: Boolean = false,
    var userAgent: String? = null,
    var requestHeaders: String? = null,
    /** Decode the fetched body when it arrives as a base64 blob/plain lines. */
    var decodeBase64ToText: Boolean = false,
    /** Convert custom JSON configs in the body into regular share links on update. */
    var convertCustomToLinks: Boolean = false,
)

