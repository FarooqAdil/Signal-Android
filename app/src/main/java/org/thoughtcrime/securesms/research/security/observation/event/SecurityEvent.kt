package org.thoughtcrime.securesms.research.security.observation

// Kinds of security events supported by the framework
internal enum class SecurityEventType {
    DEV_TEST,
    RECEIPT,
    TX_AUDIO,
    TX_VIDEO,
    CALL_ACCEPTANCE
}

// Interface for security-relevant events sent to detectors
internal interface SecurityEvent {
    val type: SecurityEventType
}

//*****************
// Security Events:

// Self-Test Event for simulation
internal data class DevTestSecurityEvent(
  override val type: SecurityEventType = SecurityEventType.DEV_TEST,
  val requestedAtMillis: Long,
  val firedAtMillis: Long
) : SecurityEvent