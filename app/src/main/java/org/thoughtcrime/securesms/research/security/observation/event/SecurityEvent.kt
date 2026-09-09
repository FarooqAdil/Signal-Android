package org.thoughtcrime.securesms.research.security.observation

// Kinds of security events supported by the framework
internal enum class SecurityEventType {
    DEV_TEST,
    RECEIPT,
    TX_AUDIO,
    TX_VIDEO,
    CALL_START,
    CALL_ACCEPTANCE
}

// Interface for security-relevant events sent to detectors
internal interface SecurityEvent {
    val type: SecurityEventType
}

//*****************
// Security Events:
//*****************


// Self-Test Event for simulation
internal data class DevTestSecurityEvent(
  override val type: SecurityEventType = SecurityEventType.DEV_TEST,
  val requestedAtMillis: Long,
  val firedAtMillis: Long
) : SecurityEvent




// The kind of receipt
internal enum class ReceiptType {
  DELIVERY,
  READ,
  VIEWED
}

// Cause of the receipt decision where Signal can determine it
internal enum class ReceiptTriggerCategory {
  MESSAGE,
  REACTION,
  DELETE,
  EDIT,
  OTHER
}

// Security event for receipt events
internal data class ReceiptSecurityEvent(
  override val type: SecurityEventType = SecurityEventType.RECEIPT,
  val receiptType: ReceiptType,
  val triggerCategory: ReceiptTriggerCategory,
  val peerId: String,
  val peerDisplayName: String,
  val messageId: String,
  val observedAtMillis: Long = System.currentTimeMillis()
) : SecurityEvent



// call direction
internal enum class CallDirection {
  INCOMING,
  OUTGOING,
  UNKNOWN
}

// outgoing media kind
internal enum class MediaKind {
  AUDIO,
  VIDEO
}



// security event for recording one-to-one call context
internal data class CallStartedSecurityEvent(
  override val type: SecurityEventType = SecurityEventType.CALL_START,
  val callId: Long,
  val callDirection: CallDirection,
  val peerId: String,
  val observedAtMillis: Long = System.currentTimeMillis()
) : SecurityEvent



// security event for call acceptance
internal data class CallAcceptanceSecurityEvent(
  override val type: SecurityEventType = SecurityEventType.CALL_ACCEPTANCE,
  val callId: Long,
  val peerId: String,
  val observedAtMillis: Long = System.currentTimeMillis()
) : SecurityEvent


// security event for media transmission actioning
internal data class MediaTxSecurityEvent(
  val callId: Long,
  val mediaKind: MediaKind,
  val enabled: Boolean,
  val peerId: String,
  val observedAtMillis: Long = System.currentTimeMillis()
) : SecurityEvent {

  override val type: SecurityEventType =
    when (mediaKind) {
      MediaKind.AUDIO -> SecurityEventType.TX_AUDIO
      MediaKind.VIDEO -> SecurityEventType.TX_VIDEO
    }
}