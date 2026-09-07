package org.thoughtcrime.securesms.research.security.observation

import java.util.UUID

// Whether a detector observed a possible security incident
internal enum class FindingType {
  POSITIVE,
  NEGATIVE
}

// User actions that may be offered for a finding
internal enum class FindingAction {
  REPORT_INCIDENT,
  REPORT_USER,
  BLOCK_USER,
  SHARE_LOGS,
  SHARE_TELEMETRY,
}

// Common result produced by security detectors
internal data class SecurityFinding(
  val findingId: String = UUID.randomUUID().toString(),
  val detectorId: String,
  val type: FindingType,
  val title: String,
  val explanation: String,
  val developerDetails: String,
  val possibleActions: Set<FindingAction> = emptySet(),
  val actionMetadata: Map<FindingAction, List<Any>> = emptyMap(),
  val observationTime: Long = System.currentTimeMillis()
)