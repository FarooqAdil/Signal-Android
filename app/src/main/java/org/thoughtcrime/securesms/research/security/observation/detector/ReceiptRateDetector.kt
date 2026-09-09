package org.thoughtcrime.securesms.research.security.observation

import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// Profile class for receipt event characteristics and activity to flag
internal data class ReceiptDetectionProfile(
  val profileId: String,
  val receiptType: ReceiptType,
  val triggerCategories: Set<ReceiptTriggerCategory> = emptySet(),
  val thresholdCount: Int,
  val windowMillis: Long,
  val alertQuantumMillis: Long,
  val correlateByMessage: Boolean = false
) {

  init {
    require(profileId.isNotBlank()) {"profileId must not be blank"}
    require(thresholdCount > 0) {"thresholdCount must be greater than zero"}
    require(windowMillis > 0) {"windowMillis must be greater than zero"}
    require(alertQuantumMillis > 0) {"alertQuantumMillis must be greater than zero"}
    require(alertQuantumMillis < windowMillis) {"alertQuantumMillis must be smaller than windowMillis"}
  }

  fun matches(event: ReceiptSecurityEvent): Boolean {
    if (event.receiptType != receiptType) {
      return false
    }
    
    return triggerCategories.isEmpty() || event.triggerCategory in triggerCategories
  }
}

// Receipt rate detector - 
internal object ReceiptRateDetector : SecurityDetector {

  override val detectorId: String = "receipt-rate"
  override val accepts = setOf(SecurityEventType.RECEIPT)
  
  
  // Receipt detector profiles
  private val profiles = listOf(
    ReceiptDetectionProfile(
      profileId = "receipt-rate",
      receiptType = ReceiptType.DELIVERY,
      thresholdCount = 10,
      windowMillis = 20_000,
      alertQuantumMillis = 5_000
    ),
    ReceiptDetectionProfile(
      profileId = "reaction-rate",
      receiptType = ReceiptType.DELIVERY,
      triggerCategories = setOf(ReceiptTriggerCategory.REACTION),
      thresholdCount = 5,
      windowMillis = 10_000, 
      alertQuantumMillis = 2_500
    ),
    ReceiptDetectionProfile(
      profileId = "reaction-target-rate",
      receiptType = ReceiptType.DELIVERY,
      triggerCategories = setOf(ReceiptTriggerCategory.REACTION),
      thresholdCount = 4,
      windowMillis = 10_000, 
      alertQuantumMillis = 2_500,
      correlateByMessage = true
    )
  )
  
  
  // lock for synchronisation - hooks/simulator may call from different threads
  private val lock = Any()

  // uniquely identifies one detector evaluation scope
  private data class DetectionScope(
    val profileId: String,
    val peerPseudoId: String,
    val messagePseudoId: String? = null
  )

  // sliding-window state for one scope
  private data class WindowState(
    val timestamps: MutableList<Long> = mutableListOf(),
    var lastPositiveFindingAtMillis: Long? = null
  )

  // all active receipt detection windows
  private val windowStates = mutableMapOf<DetectionScope, WindowState>()
  
  
  // Independent process-lifetime keys for peer and message pseudonymisation
  private var peerKey: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
  private var messageKey: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

  // Generates a deterministic process-local pseudonym for an identifier
  private fun pseudonymise(key: ByteArray, rawId: String): String {
    val hmac = Mac.getInstance("HmacSHA256")
    hmac.init(SecretKeySpec(key, "HmacSHA256"))
    val digest = hmac.doFinal(rawId.toByteArray(Charsets.UTF_8))

    return digest.joinToString("") { byte ->
        "%02x".format(byte.toInt() and 0xff)
    }
  }

  // Pseudonymises a raw peer identifier
  private fun pseudonymisePeer(peerId: String): String {
    return pseudonymise(peerKey, peerId)
  }

  // Pseudonymises a raw message identifier
  private fun pseudonymiseMessage(messageId: String): String {
    return pseudonymise(messageKey, messageId)
  }

  
  // process security events based on profiles
  override fun process(event: SecurityEvent): List<SecurityFinding> {
    val receiptEvent = event as? ReceiptSecurityEvent ?: return emptyList()

    return synchronized(lock) {
        cleanupStaleWindows(receiptEvent.observedAtMillis)
        
        val peerPseudoId = pseudonymisePeer(receiptEvent.peerId)
        val messagePseudoId = pseudonymiseMessage(receiptEvent.messageId)

        val findings = mutableListOf<SecurityFinding>()

        for (profile in profiles) {
            if (profile.matches(receiptEvent)) {
                findings += evaluateProfile(
                    event = receiptEvent,
                    profile = profile,
                    peerPseudoId = peerPseudoId,
                    messagePseudoId = messagePseudoId
                )
            }
        }
        findings
    }
  }

  
  // Evaluates one receipt event against one detection profile
  private fun evaluateProfile(event: ReceiptSecurityEvent, profile: ReceiptDetectionProfile, peerPseudoId: String, messagePseudoId: String): List<SecurityFinding> {

    val scope = DetectionScope(profile.profileId, peerPseudoId, if (profile.correlateByMessage) messagePseudoId else null)

    val state = windowStates.getOrPut(scope) { WindowState() }

    // Remove observations that have fallen outside this profile's time window
    val windowStart = event.observedAtMillis - profile.windowMillis

    state.timestamps.removeAll { it < windowStart }

    // Add the current receipt observation
    state.timestamps.add(event.observedAtMillis)

    val observationCount = state.timestamps.size
    val thresholdExceeded = observationCount >= profile.thresholdCount

    if (thresholdExceeded) {
        val lastPositive = state.lastPositiveFindingAtMillis
        val quantumElapsed = lastPositive == null || event.observedAtMillis - lastPositive >= profile.alertQuantumMillis

        if (quantumElapsed) {
            state.lastPositiveFindingAtMillis = event.observedAtMillis
            return listOf(createReceiptRateFinding(event, profile, peerPseudoId, observationCount, state.timestamps.toList()))
        }
    }
    
    // Every non-positive evaluation produces a negative finding
    return listOf(createReceiptRateNegativeFinding(event, profile, peerPseudoId, observationCount, thresholdExceeded))
  }
  
  
  // Removes detection scopes whose observations can no longer affect a profile
  private fun cleanupStaleWindows(currentTimeMillis: Long) {
    val iterator = windowStates.iterator()

    while (iterator.hasNext()) {
        val entry = iterator.next()
        val scope = entry.key
        val state = entry.value

        val profile = profiles.firstOrNull { it.profileId == scope.profileId}

        if (profile == null || state.timestamps.isEmpty()) {
            iterator.remove()
            continue
        }

        val newestObservation = state.timestamps.maxOrNull() ?: continue

        if (currentTimeMillis - newestObservation > profile.windowMillis) {
            iterator.remove()
        }
    }
  }
    
  
  // Positive Security finding: configured receipt-rate threshold exceeded
  private fun createReceiptRateFinding(event: ReceiptSecurityEvent, profile: ReceiptDetectionProfile, peerPseudoId: String, observationCount: Int, timestamps: List<Long>): SecurityFinding {

    val peerRef = peerPseudoId.take(8)
    val peerId = event.peerId

    return SecurityFinding(
        detectorId = detectorId,
        type = FindingType.POSITIVE,
        title = "Unusual receipt activity detected",
        explanation = "Signal observed an unusually high rate of ${event.triggerCategory.name.lowercase()} receipt activity being generated due to a the same user: ${event.peerDisplayName} (${peerId}). This may indicate automated probing or other abnormal activity.",
        developerDetails ="Receipt detection profile threshold exceeded. \n" +
            "Profile=${profile.profileId}; \n" +
            "Receipt=${event.receiptType}; \n" +
            "Trigger=${event.triggerCategory}; \n" +
            "Peer=$peerRef; \n" +
            "Count=$observationCount; \n" +
            "Threshold=${profile.thresholdCount}; \n" +
            "Window=${profile.windowMillis}ms; \n" +
            "Quantum=${profile.alertQuantumMillis}ms; \n" +
            "MessageCorrelation=${profile.correlateByMessage}.",
        possibleActions = FindingAction.entries.toSet(),
        actionMetadata = mapOf(FindingAction.REPORT_USER to listOf(peerId), FindingAction.BLOCK_USER to listOf(peerId), FindingAction.SHARE_TELEMETRY to timestamps.map { it as Any }),
        observationTime = event.observedAtMillis
    )
  }
  
  
  // Negative Security finding: receipt event did not generate a new positive incident
  private fun createReceiptRateNegativeFinding(event: ReceiptSecurityEvent, profile: ReceiptDetectionProfile, peerPseudoId: String, observationCount: Int, thresholdExceeded: Boolean): SecurityFinding {

    val peerRef = peerPseudoId.take(8)

    val resultText = if (thresholdExceeded) {
        "Threshold exceeded, but a positive finding was already generated within the current alert quantum."} else 
        {"Receipt activity remains below the configured threshold."}

    return SecurityFinding(
        detectorId = detectorId,
        type = FindingType.NEGATIVE,
        title = "Receipt activity evaluated",
        explanation = resultText,
        developerDetails = "Receipt detection profile evaluated. \n" +
            "Profile=${profile.profileId}; \n" +
            "Receipt=${event.receiptType}; \n" +
            "Trigger=${event.triggerCategory}; \n" +
            "Peer=$peerRef; \n" +
            "Count=$observationCount; \n" +
            "Threshold=${profile.thresholdCount}; \n" +
            "Window=${profile.windowMillis}ms; \n" +
            "Quantum=${profile.alertQuantumMillis}ms; \n" +
            "ThresholdExceeded=$thresholdExceeded.",
        possibleActions = emptySet(),
        actionMetadata = emptyMap(),
        observationTime = event.observedAtMillis
    )
  }
 
  
  override fun clear() {
    synchronized(lock) {
      windowStates.clear()

      peerKey.fill(0)
      messageKey.fill(0)
    }
  }
}
