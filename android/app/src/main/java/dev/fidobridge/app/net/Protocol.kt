package dev.fidobridge.app.net

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonClassDiscriminator

val bridgeJson = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    classDiscriminator = "type"
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@JsonClassDiscriminator("type")
sealed class BridgeMessage {
    abstract val id: String

    @Serializable
    @SerialName("hello")
    data class Hello(
        override val id: String,
        val name: String,
        val aaguid: String? = null,
        val versions: List<String> = emptyList(),
    ) : BridgeMessage()

    @Serializable
    @SerialName("ping")
    data class Ping(override val id: String, val ts: Long) : BridgeMessage()

    @Serializable
    @SerialName("pong")
    data class Pong(override val id: String, val ts: Long) : BridgeMessage()

    @Serializable
    @SerialName("ctap_request")
    data class CtapRequest(
        override val id: String,
        val cmd: String,
        @SerialName("timeout_ms") val timeoutMs: Long = 60_000,
        @SerialName("rp_id") val rpId: String? = null,
    ) : BridgeMessage()

    @Serializable
    @SerialName("ctap_cancel")
    data class CtapCancel(override val id: String) : BridgeMessage()

    @Serializable
    @SerialName("ctap_response")
    data class CtapResponse(
        override val id: String,
        val status: String,
        val data: String? = null,
        val error: String? = null,
        @SerialName("ctap_status") val ctapStatus: Int? = null,
    ) : BridgeMessage()
}
