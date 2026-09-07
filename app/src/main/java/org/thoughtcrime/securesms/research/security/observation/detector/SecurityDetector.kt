package org.thoughtcrime.securesms.research.security.observation

// Interface for security incident detectors
internal interface SecurityDetector {
  val detectorId: String
  
  val accepts: Set<SecurityEventType>

  fun process(event: SecurityEvent): List<SecurityFinding>

  fun clear()
}