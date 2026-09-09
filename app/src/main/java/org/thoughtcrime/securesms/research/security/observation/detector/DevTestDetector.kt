package org.thoughtcrime.securesms.research.security.observation

import org.signal.core.util.logging.Log

// Detector used to verify the framework event-to-finding pipeline
internal object DevTestDetector : SecurityDetector {

  override val detectorId = "DEV_SELF_TEST"

  override val accepts = setOf(SecurityEventType.DEV_TEST)

  override fun process(event: SecurityEvent): List<SecurityFinding> {
    if (event !is DevTestSecurityEvent) {
      Log.e(ERROR_TAG, "DevTestDetector received incompatible event: ${event.type}")
      return emptyList()
    }

    val actualDelay = event.firedAtMillis - event.requestedAtMillis

    Log.i(INFO_TAG, "DevTestDetector processed the test event. Actual delay: ${actualDelay}ms")

    return listOf(
      SecurityFinding(
        detectorId = detectorId,
        type = FindingType.POSITIVE,
        title = "Framework Self-Test: Dev Event-to-Finding",
        explanation = "A scheduled development self-test has successfully traversed the security observation framework.",
        developerDetails =
          "Requested: ${event.requestedAtMillis}\n" +
          "Fired: ${event.firedAtMillis}\n" +
          "Actual delay: ${actualDelay}ms",
        possibleActions = FindingAction.entries.toSet(),
        actionMetadata = mapOf(
          FindingAction.REPORT_USER to listOf("dev-test-peer"),
          FindingAction.BLOCK_USER to listOf("dev-test-peer")
        ),
      )
    )
  }

  override fun clear() {
    Log.i(INFO_TAG, "DevTestDetector cleared")
  }
}