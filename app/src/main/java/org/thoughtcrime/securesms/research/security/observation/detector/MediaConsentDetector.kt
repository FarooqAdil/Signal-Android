package org.thoughtcrime.securesms.research.security.observation

// Media Consent Detector - flags media transmission before user acceptance
internal object MediaConsentDetector : SecurityDetector {

  override val detectorId: String = "media-consent-order"
  override val accepts = 
      setOf(SecurityEventType.TX_AUDIO, SecurityEventType.TX_VIDEO, SecurityEventType.CALL_START, SecurityEventType.CALL_ACCEPTANCE)

  // lock for synchronisation - hooks may call from different threads
  private val lock = Any()

  private data class CallState(
    var callDirection: CallDirection = CallDirection.UNKNOWN,
    var peerId: String? = null,
    var acceptedAtMillis: Long? = null,
    val evaluatedMedia: MutableSet<MediaKind> = mutableSetOf()
  )
  private val callStates = mutableMapOf<Long, CallState>()

  // sorts events and sends to respective processors
  override fun process(event: SecurityEvent): List<SecurityFinding> {
    return synchronized(lock) {
      when (event) {
        is CallStartedSecurityEvent -> processCallStart(event)
        is CallAcceptanceSecurityEvent -> processAcceptance(event)
        is MediaTxSecurityEvent -> processMedia(event)
        else -> emptyList()
      }
    }
  }

  // stores known context for a call without overwriting prior detector state
  private fun processCallStart(event: CallStartedSecurityEvent): List<SecurityFinding> {
    val state = callStates.getOrPut(event.callId) { CallState() }

    if (state.callDirection == CallDirection.UNKNOWN) {
      state.callDirection = event.callDirection
    }

    if (state.peerId == null) {
      state.peerId = event.peerId
    }

    return emptyList()
  } 
  
  // processes a call acceptance event
  private fun processAcceptance(event: CallAcceptanceSecurityEvent): List<SecurityFinding> {
    val state = callStates.getOrPut(event.callId) { CallState() }

    if (state.peerId == null) {
      state.peerId = event.peerId
    }
    
    // in case of double acceptance, earliest stamp desired
    if (state.acceptedAtMillis == null) {
      state.acceptedAtMillis = event.observedAtMillis
    }

    return emptyList()
  }

  // processes a media transmission event
  private fun processMedia(event: MediaTxSecurityEvent): List<SecurityFinding> {
    // media disabled
    if (!event.enabled) {
      return emptyList()
    }

    val state = callStates.getOrPut(event.callId) { CallState() }
    
    if (state.peerId == null) {
      state.peerId = event.peerId
    }
    
    if (state.callDirection == CallDirection.OUTGOING) {
      return emptyList()
    }
    
    // Only evaluate the first outgoing tx of each media kind per call
    if (!state.evaluatedMedia.add(event.mediaKind)) { // if mediatype in set
      return emptyList()
    }
    
    if (state.callDirection == CallDirection.UNKNOWN) {
      return listOf(createMissingCallStartFinding(event))
    }
    
    val acceptedAtMillis = state.acceptedAtMillis // accepted time or null

    // if media tx occurred after acceptance
    return if (acceptedAtMillis != null && acceptedAtMillis <= event.observedAtMillis) {
        listOf(createConsentPreservedFinding(event, acceptedAtMillis))
      } else {
        listOf(createConsentViolationFinding(event, acceptedAtMillis))
      }
  }

  // Positive Security finding: media tx before/without acceptance/consent
  private fun createConsentViolationFinding(event: MediaTxSecurityEvent, acceptedAtMillis: Long?): SecurityFinding {
    val mediaLabel = event.mediaKind.name.lowercase()
    val callReference = shortCallReference(event.callId)
    val peerId = event.peerId

    return SecurityFinding(
      detectorId = detectorId,
      type = FindingType.POSITIVE,
      title = "Outgoing $mediaLabel enabled before local acceptance",
      explanation = "Signal Android requested outgoing $mediaLabel media transmission before the framework observed local acceptance of the same incoming call. This is a potential media-consent ordering violation.",
      developerDetails = "Local acceptance must precede outgoing media enablement. \n" +
          "Call=$callReference; \n" +
          "Acceptance=${acceptedAtMillis ?: "not-observed"}; \n" +
          "Media=${event.observedAtMillis}; \n" +
          "Boundary=Signal Android media-enable/handoff; \n" +
          "This finding does not establish packet-level RTP transmission.",
      possibleActions = FindingAction.entries.toSet(),
      actionMetadata = mapOf(FindingAction.REPORT_USER to listOf(peerId), FindingAction.BLOCK_USER to listOf(peerId)),
      observationTime = event.observedAtMillis
    )
  }

  // Negative Security finding: media tx after/with acceptance/consent
  private fun createConsentPreservedFinding(event: MediaTxSecurityEvent, acceptedAtMillis: Long): SecurityFinding {
    val mediaLabel = event.mediaKind.name.lowercase()
    val callReference = shortCallReference(event.callId)
    //val peerId = event.peerId

    return SecurityFinding(
      detectorId = detectorId,
      type = FindingType.NEGATIVE,
      title = "Media consent order preserved",
      explanation = "Local call acceptance was observed before Signal Android requested outgoing $mediaLabel media transmission for the same incoming call.",
      developerDetails = "Invariant preserved. \n" +
          "Call=$callReference; \n" +
          "Acceptance=$acceptedAtMillis; \n" +
          "Media=${event.observedAtMillis}; \n" +
          "Boundary=Signal Android media-enable/handoff; \n" +
          "This finding does not establish packet-level RTP transmission.",
      possibleActions = emptySet(),
      actionMetadata = emptyMap(),
      observationTime = event.observedAtMillis
    )
  }

  
  // Positive Security finding: media was enabled without observed call start
  private fun createMissingCallStartFinding(event: MediaTxSecurityEvent): SecurityFinding {

    val mediaLabel = event.mediaKind.name.lowercase()
    val callReference = shortCallReference(event.callId)
    val peerId = event.peerId

    return SecurityFinding(
      detectorId = detectorId,
      type = FindingType.POSITIVE,
      title = "Media enabled without observed call start",
      explanation = "Signal Android requested outgoing $mediaLabel media transmission, but the framework had not observed the expected call start for this session.",
      developerDetails = "Call start unavailable. \n" +
        "Call=$callReference; \n" +
        "Media=${event.observedAtMillis}; \n" +
        "Boundary=Signal Android media-enable/handoff; \n" +
        "Direction=UNKNOWN.",
      possibleActions = FindingAction.entries.toSet(),
      actionMetadata = mapOf(
        FindingAction.REPORT_USER to listOf(peerId),
        FindingAction.BLOCK_USER to listOf(peerId)
      ),
      observationTime = event.observedAtMillis
    )
  }
  
  
  private fun shortCallReference(callId: Long): String {
    return java.lang.Long.toUnsignedString(callId, 16).takeLast(8)
  }

  // clears call states in a thread safe manner
  override fun clear() {
    synchronized(lock) {
      callStates.clear()
    }
  }
}