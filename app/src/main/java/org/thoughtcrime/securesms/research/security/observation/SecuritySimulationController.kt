package org.thoughtcrime.securesms.research.security.observation

import android.os.Handler
import android.os.Looper
import org.signal.core.util.logging.Log
import android.os.SystemClock

// One event to be scheduled by the simulation controller
internal data class SimulationEvent(val description: String, val createEvent: (Long) -> SecurityEvent)

// One event plus its delay from the previous event
internal data class SimulationStep(val afterPreviousMillis: Long, val event: SimulationEvent)


// Controller for framework self-tests and security simulations
internal object SecuritySimulationController {

  private const val SELF_TEST_DELAY_MS = 20_000L
  private const val DEFAULT_EVENT_SPACING_MS = 50L

  private val handler = Handler(Looper.getMainLooper())

  // Schedules one generic framework self-test event
  fun fireSelfTest() {
    val requestedAt = System.currentTimeMillis()

    Log.i(INFO_TAG, "Framework self-test scheduled for ${SELF_TEST_DELAY_MS}ms delay at $requestedAt")

    handler.postDelayed({
      val firedAt = System.currentTimeMillis()

      Log.i(INFO_TAG, "Framework self-test event firing at $firedAt; requested at $requestedAt")

      SecurityTelemetryEngine.submitEvent(DevTestSecurityEvent(requestedAtMillis = requestedAt, firedAtMillis = firedAt))
    }, SELF_TEST_DELAY_MS)
  }
  
  
  // ********************
  // Helpers
  // ********************

  // Queues uniformly-spaced events. Observation time is captured when each event actually fires.
  fun queueEvents(scenarioId: String, events: List<SimulationEvent>, spacingMillis: Long = DEFAULT_EVENT_SPACING_MS, onComplete: () -> Unit = {}) {
    val steps = events.mapIndexed { index, event -> SimulationStep(afterPreviousMillis = if (index == 0) 0L else spacingMillis, event = event) }
    queueSteps(scenarioId, steps, onComplete)
  }

  // Queues events with individually-defined real-time delays from the preceding event.
  fun queueSteps(scenarioId: String, steps: List<SimulationStep>, onComplete: () -> Unit = {}) {
    if (steps.isEmpty()) { onComplete(); return }

    val totalDuration = steps.sumOf { it.afterPreviousMillis }
    Log.i(INFO_TAG, "[SIM QUEUE][$scenarioId] steps=${steps.size} scheduled-duration=${totalDuration}ms")

    var cumulativeDelay = 0L

    steps.forEachIndexed { index, step ->
      cumulativeDelay += step.afterPreviousMillis

      handler.postDelayed({
        val observedAtMillis = SystemClock.elapsedRealtime()
        val event = step.event.createEvent(observedAtMillis)

        Log.i(INFO_TAG, "[SIM EVENT][$scenarioId] ${index + 1}/${steps.size} ${step.event.description} t=$observedAtMillis")

        SecurityTelemetryEngine.submitEvent(event)

        if (index == steps.lastIndex) onComplete()
      }, cumulativeDelay)
    }
  }

  // Creates one scheduled receipt event for composition into larger scenarios.
  fun receiptStep(afterPreviousMillis: Long, triggerCategory: ReceiptTriggerCategory, peerId: String, messageId: String, receiptType: ReceiptType = ReceiptType.DELIVERY, peerDisplayName: String = "Simulation Peer"): SimulationStep {
    
    val event = SimulationEvent("RECEIPT type=$receiptType trigger=$triggerCategory peer=$peerId message=$messageId") { observedAtMillis ->
      ReceiptSecurityEvent(receiptType = receiptType, triggerCategory = triggerCategory, peerId = peerId, peerDisplayName = peerDisplayName, messageId = messageId, observedAtMillis = observedAtMillis)
    }

    return SimulationStep(afterPreviousMillis = afterPreviousMillis, event = event)
  }

  // Creates a repeated receipt burst without scheduling it yet, allowing multiple bursts/gaps to be composed.
  fun receiptBurstSteps(count: Int, spacingMillis: Long, triggerCategory: ReceiptTriggerCategory, sameMessage: Boolean, peerId: String, messagePrefix: String, firstDelayMillis: Long = 0L, receiptType: ReceiptType = ReceiptType.DELIVERY, peerDisplayName: String = "Simulation Peer"): List<SimulationStep> {
    
    return List(count) { index ->
      val messageId = if (sameMessage) messagePrefix else "$messagePrefix-${index + 1}"
      val delay = if (index == 0) firstDelayMillis else spacingMillis

      receiptStep(delay, triggerCategory, peerId, messageId, receiptType, peerDisplayName)
    }
  }

  // Convenience method for one uniformly-spaced real-time receipt burst.
  fun queueReceiptBurst(scenarioId: String, count: Int, spacingMillis: Long, triggerCategory: ReceiptTriggerCategory, sameMessage: Boolean, peerId: String = "simulation-peer-$scenarioId", receiptType: ReceiptType = ReceiptType.DELIVERY, onComplete: () -> Unit = {}) {
    
    val steps = receiptBurstSteps(count, spacingMillis, triggerCategory, sameMessage, peerId, "simulation-message-$scenarioId", receiptType = receiptType, peerDisplayName = "Simulation Peer $scenarioId")
    queueSteps(scenarioId, steps, onComplete)
    
  } 
  
  
}