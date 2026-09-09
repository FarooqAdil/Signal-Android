package org.thoughtcrime.securesms.research.security.observation

import org.signal.core.util.logging.Log

internal object SecurityEvaluationController {

  private fun runScenario(id: String, description: String, expected: String, onComplete: () -> Unit = {}, simulation: (() -> Unit) -> Unit) {
    Log.i(INFO_TAG, "==================================================")
    Log.i(INFO_TAG, "[EVAL START][$id] $description")
    Log.i(INFO_TAG, "[EVAL EXPECTED][$id] $expected")

    simulation {
      Log.i(INFO_TAG, "[EVAL END][$id] Simulation inputs complete. Inspect detector/finding logs between START and END.")
      Log.i(INFO_TAG, "==================================================")

      onComplete()
    }
  }

  // A1 — normal incoming audio
  // events: 3
  // sequence: CALL_START(INCOMING) -> ACCEPT -> AUDIO(true)
  // timing: default scheduler spacing = 50ms
  // expected: 1 NEGATIVE media-consent finding
  fun runA1(onComplete: () -> Unit = {}) {
    
    runScenario("A1", "Incoming call accepted before outgoing audio", "NEGATIVE media-consent finding: invariant preserved.", onComplete) { done ->
      val callId = 10_001L
      val peerId = "simulation-peer-A1"

      SecuritySimulationController.queueEvents("A1", listOf(
        SimulationEvent("CALL_START(INCOMING)") { t -> CallStartedSecurityEvent(callId = callId, callDirection = CallDirection.INCOMING, peerId = peerId, observedAtMillis = t) },
        SimulationEvent("CALL_ACCEPTANCE") { t -> CallAcceptanceSecurityEvent(callId = callId, peerId = peerId, observedAtMillis = t) },
        SimulationEvent("TX_AUDIO enabled=true") { t -> MediaTxSecurityEvent(callId = callId, mediaKind = MediaKind.AUDIO, enabled = true, peerId = peerId, observedAtMillis = t) }
      ), onComplete = done)
    }
  }

  // A3 — normal incoming audio and video
  // events: 4
  // sequence: CALL_START(INCOMING) -> ACCEPT -> AUDIO(true) -> VIDEO(true)
  // timing: default scheduler spacing = 50ms
  // expected: 2 NEGATIVE media-consent findings
  fun runA3(onComplete: () -> Unit = {}) {
    runScenario("A3", "Incoming call accepted before outgoing audio and video", "Two NEGATIVE findings: AUDIO and VIDEO preserve the consent invariant.", onComplete) { done ->
      val callId = 10_003L
      val peerId = "simulation-peer-A3"

      SecuritySimulationController.queueEvents("A3", listOf(
        SimulationEvent("CALL_START(INCOMING)") { t -> CallStartedSecurityEvent(callId = callId, callDirection = CallDirection.INCOMING, peerId = peerId, observedAtMillis = t) },
        SimulationEvent("CALL_ACCEPTANCE") { t -> CallAcceptanceSecurityEvent(callId = callId, peerId = peerId, observedAtMillis = t) },
        SimulationEvent("TX_AUDIO enabled=true") { t -> MediaTxSecurityEvent(callId = callId, mediaKind = MediaKind.AUDIO, enabled = true, peerId = peerId, observedAtMillis = t) },
        SimulationEvent("TX_VIDEO enabled=true") { t -> MediaTxSecurityEvent(callId = callId, mediaKind = MediaKind.VIDEO, enabled = true, peerId = peerId, observedAtMillis = t) }
      ), onComplete = done)
    }
  }

  // A4 — audio before acceptance
  // events: 3
  // sequence: CALL_START(INCOMING) -> AUDIO(true) -> ACCEPT
  // timing: default scheduler spacing = 50ms
  // expected: 1 POSITIVE consent-order violation
  fun runA4(onComplete: () -> Unit = {}) {
    runScenario("A4", "Outgoing audio enabled before incoming call acceptance", "POSITIVE media-consent-order violation.", onComplete) { done ->
      val callId = 10_004L
      val peerId = "simulation-peer-A4"

      SecuritySimulationController.queueEvents("A4", listOf(
        SimulationEvent("CALL_START(INCOMING)") { t -> CallStartedSecurityEvent(callId = callId, callDirection = CallDirection.INCOMING, peerId = peerId, observedAtMillis = t) },
        SimulationEvent("TX_AUDIO enabled=true") { t -> MediaTxSecurityEvent(callId = callId, mediaKind = MediaKind.AUDIO, enabled = true, peerId = peerId, observedAtMillis = t) },
        SimulationEvent("CALL_ACCEPTANCE") { t -> CallAcceptanceSecurityEvent(callId = callId, peerId = peerId, observedAtMillis = t) }
      ), onComplete = done)
    }
  }

  // A6 — audio and video before acceptance
  // events: 4
  // sequence: CALL_START(INCOMING) -> AUDIO(true) -> VIDEO(true) -> ACCEPT
  // timing: default scheduler spacing = 50ms
  // expected: 2 POSITIVE consent-order violations
  fun runA6(onComplete: () -> Unit = {}) {
    runScenario("A6", "Outgoing audio and video enabled before incoming call acceptance", "Two POSITIVE consent-order violations: AUDIO and VIDEO.", onComplete) { done ->
      val callId = 10_006L
      val peerId = "simulation-peer-A6"

      SecuritySimulationController.queueEvents("A6", listOf(
        SimulationEvent("CALL_START(INCOMING)") { t -> CallStartedSecurityEvent(callId = callId, callDirection = CallDirection.INCOMING, peerId = peerId, observedAtMillis = t) },
        SimulationEvent("TX_AUDIO enabled=true") { t -> MediaTxSecurityEvent(callId = callId, mediaKind = MediaKind.AUDIO, enabled = true, peerId = peerId, observedAtMillis = t) },
        SimulationEvent("TX_VIDEO enabled=true") { t -> MediaTxSecurityEvent(callId = callId, mediaKind = MediaKind.VIDEO, enabled = true, peerId = peerId, observedAtMillis = t) },
        SimulationEvent("CALL_ACCEPTANCE") { t -> CallAcceptanceSecurityEvent(callId = callId, peerId = peerId, observedAtMillis = t) }
      ), onComplete = done)
    }
  }

  // B1 — missing call-start context
  // events: 1
  // sequence: AUDIO(true)
  // timing: immediate
  // expected: 1 POSITIVE missing-CALL_START/context finding
  fun runB1(onComplete: () -> Unit = {}) {
    runScenario("B1", "Outgoing audio observed without call-start context", "POSITIVE missing-CALL_START/context finding.", onComplete) { done ->
      SecuritySimulationController.queueEvents("B1", listOf(
        SimulationEvent("TX_AUDIO enabled=true; no CALL_START") { t -> MediaTxSecurityEvent(callId = 20_001L, mediaKind = MediaKind.AUDIO, enabled = true, peerId = "simulation-peer-B1", observedAtMillis = t) }
      ), onComplete = done)
    }
  }

  // C1 — generic receipt rate immediately below threshold
  // receipts: 9 DELIVERY / MESSAGE
  // correlation: same peer, distinct messages
  // timing: 100ms spacing; total span approximately 800ms
  // expected: no generic POSITIVE
  fun runC1(onComplete: () -> Unit = {}) {
    runScenario("C1", "Nine ordinary delivery receipts inside the generic 20-second window", "No generic POSITIVE; count remains below threshold 10.", onComplete) { done ->
      SecuritySimulationController.queueReceiptBurst("C1", count = 9, spacingMillis = 100L, triggerCategory = ReceiptTriggerCategory.MESSAGE, sameMessage = false, onComplete = done)
    }
  }

  // C2 — exact generic receipt-rate threshold
  // receipts: 10 DELIVERY / MESSAGE
  // correlation: same peer, distinct messages
  // timing: 100ms spacing; total span approximately 900ms
  // expected: generic receipt-rate POSITIVE on receipt 10
  fun runC2(onComplete: () -> Unit = {}) {
    runScenario("C2", "Ten ordinary delivery receipts inside the generic 20-second window", "Generic receipt-rate POSITIVE on receipt 10.", onComplete) { done ->
      SecuritySimulationController.queueReceiptBurst("C2", count = 10, spacingMillis = 100L, triggerCategory = ReceiptTriggerCategory.MESSAGE, sameMessage = false, onComplete = done)
    }
  }

  // C3 — generic sliding-window expiry
  // receipts: 10 DELIVERY / MESSAGE
  // correlation: same peer, distinct messages
  // timing: 2500ms spacing; total span approximately 22.5s
  // expected: no generic POSITIVE because fewer than 10 coexist inside the 20s window
  fun runC3(onComplete: () -> Unit = {}) {
    runScenario("C3", "Ten ordinary deliveries spread beyond the 20-second sliding window", "No generic POSITIVE: fewer than 10 observations coexist in the active window.", onComplete) { done ->
      SecuritySimulationController.queueReceiptBurst("C3", count = 10, spacingMillis = 2_500L, triggerCategory = ReceiptTriggerCategory.MESSAGE, sameMessage = false, onComplete = done)
    }
  }

  // D1 — reactions below both specialised thresholds
  // receipts: 4 DELIVERY / REACTION
  // correlation: same peer, four distinct targets
  // timing: 100ms spacing
  // expected: no reaction-rate or reaction-target POSITIVE
  fun runD1(onComplete: () -> Unit = {}) {
    runScenario("D1", "Four reactions from one peer to four different messages", "No reaction-rate or reaction-target POSITIVE.", onComplete) { done ->
      SecuritySimulationController.queueReceiptBurst("D1", count = 4, spacingMillis = 100L, triggerCategory = ReceiptTriggerCategory.REACTION, sameMessage = false, onComplete = done)
    }
  }

  // D2 — repeated reactions against one target
  // receipts: 4 DELIVERY / REACTION
  // correlation: same peer, same target message
  // timing: 100ms spacing
  // expected: reaction-target-rate POSITIVE on receipt 4
  fun runD2(onComplete: () -> Unit = {}) {
    runScenario("D2", "Four reactions from one peer to the same target message", "Reaction-target-rate POSITIVE on reaction 4.", onComplete) { done ->
      SecuritySimulationController.queueReceiptBurst("D2", count = 4, spacingMillis = 100L, triggerCategory = ReceiptTriggerCategory.REACTION, sameMessage = true, onComplete = done)
    }
  }

  // D3 — reaction-rate threshold across distinct targets
  // receipts: 5 DELIVERY / REACTION
  // correlation: same peer, five distinct targets
  // timing: 100ms spacing
  // expected: reaction-rate POSITIVE on receipt 5; no target-rate POSITIVE
  fun runD3(onComplete: () -> Unit = {}) {
    runScenario("D3", "Five reactions from one peer to different target messages", "Reaction-rate POSITIVE on reaction 5; no target-rate POSITIVE.", onComplete) { done ->
      SecuritySimulationController.queueReceiptBurst("D3", count = 5, spacingMillis = 100L, triggerCategory = ReceiptTriggerCategory.REACTION, sameMessage = false, onComplete = done)
    }
  }

  // D5 — reaction activity split across peers
  // receipts: 5 DELIVERY / REACTION; peer A=3, peer B=2
  // correlation: distinct targets; counts must remain peer-local
  // timing: 100ms between all five observations
  // expected: no specialised POSITIVE
  fun runD5(onComplete: () -> Unit = {}) {
    runScenario("D5", "Five reactions divided between two distinct peers", "No reaction-rate POSITIVE because peer-scoped counts remain below threshold.", onComplete) { done ->
      val steps =
        SecuritySimulationController.receiptBurstSteps(count = 3, spacingMillis = 100L, triggerCategory = ReceiptTriggerCategory.REACTION, sameMessage = false, peerId = "simulation-peer-D5-A", messagePrefix = "simulation-message-D5-A", peerDisplayName = "Simulation Peer D5-A") +
        SecuritySimulationController.receiptBurstSteps(count = 2, spacingMillis = 100L, triggerCategory = ReceiptTriggerCategory.REACTION, sameMessage = false, peerId = "simulation-peer-D5-B", messagePrefix = "simulation-message-D5-B", firstDelayMillis = 100L, peerDisplayName = "Simulation Peer D5-B")

      SecuritySimulationController.queueSteps("D5", steps, done)
    }
  }

  // E1 — reaction alert-quantum suppression
  // receipts: 6 DELIVERY / REACTION; same peer, distinct targets
  // timing: first 5 at 100ms spacing; receipt 6 occurs 100ms after receipt 5
  // quantum: reaction-rate alert quantum = 2500ms
  // expected: POSITIVE on receipt 5; no second POSITIVE on receipt 6
  fun runE1(onComplete: () -> Unit = {}) {
    runScenario("E1", "Reaction threshold reached followed by another qualifying reaction inside the alert quantum", "Reaction-rate POSITIVE on receipt 5; no second POSITIVE on receipt 6.", onComplete) { done ->
      val peerId = "simulation-peer-E1"
      val steps =
        SecuritySimulationController.receiptBurstSteps(count = 5, spacingMillis = 100L, triggerCategory = ReceiptTriggerCategory.REACTION, sameMessage = false, peerId = peerId, messagePrefix = "simulation-message-E1", peerDisplayName = "Simulation Peer E1") +
        SecuritySimulationController.receiptStep(afterPreviousMillis = 100L, triggerCategory = ReceiptTriggerCategory.REACTION, peerId = peerId, messageId = "simulation-message-E1-6", peerDisplayName = "Simulation Peer E1")

      SecuritySimulationController.queueSteps("E1", steps, done)
    }
  }

  // E2 — reaction re-alert after alert quantum
  // receipts: 6 DELIVERY / REACTION; same peer, distinct targets
  // timing: first 5 at 100ms spacing; receipt 6 occurs 3000ms after receipt 5
  // quantum/window: 2500ms alert quantum; 10s reaction window
  // expected: POSITIVE on receipt 5 and another POSITIVE on receipt 6
  fun runE2(onComplete: () -> Unit = {}) {
    runScenario("E2", "Reaction threshold reached followed by another qualifying reaction after the alert quantum", "Reaction-rate POSITIVE on receipt 5 and another POSITIVE on receipt 6.", onComplete) { done ->
      val peerId = "simulation-peer-E2"
      val steps =
        SecuritySimulationController.receiptBurstSteps(count = 5, spacingMillis = 100L, triggerCategory = ReceiptTriggerCategory.REACTION, sameMessage = false, peerId = peerId, messagePrefix = "simulation-message-E2", peerDisplayName = "Simulation Peer E2") +
        SecuritySimulationController.receiptStep(afterPreviousMillis = 3_000L, triggerCategory = ReceiptTriggerCategory.REACTION, peerId = peerId, messageId = "simulation-message-E2-6", peerDisplayName = "Simulation Peer E2")

      SecuritySimulationController.queueSteps("E2", steps, done)
    }
  }

  // E3 — generic receipt alert-quantum suppression
  // receipts: 11 DELIVERY / MESSAGE; same peer, distinct messages
  // timing: first 10 at 100ms spacing; receipt 11 occurs 100ms after receipt 10
  // quantum: generic receipt-rate alert quantum = 5000ms
  // expected: POSITIVE on receipt 10; no second generic POSITIVE on receipt 11
  fun runE3(onComplete: () -> Unit = {}) {
    runScenario("E3", "Generic receipt threshold reached followed by another receipt inside the alert quantum", "Generic POSITIVE on receipt 10; no second generic POSITIVE on receipt 11.", onComplete) { done ->
      val peerId = "simulation-peer-E3"
      val steps =
        SecuritySimulationController.receiptBurstSteps(count = 10, spacingMillis = 100L, triggerCategory = ReceiptTriggerCategory.MESSAGE, sameMessage = false, peerId = peerId, messagePrefix = "simulation-message-E3", peerDisplayName = "Simulation Peer E3") +
        SecuritySimulationController.receiptStep(afterPreviousMillis = 100L, triggerCategory = ReceiptTriggerCategory.MESSAGE, peerId = peerId, messageId = "simulation-message-E3-11", peerDisplayName = "Simulation Peer E3")

      SecuritySimulationController.queueSteps("E3", steps, done)
    }
  }

  // Runs the currently selected evaluation scenarios sequentially.
  fun runSelectedEvaluation() {
    val selected: List<(() -> Unit) -> Unit> = listOf(
      { done -> runA1(done) },
      { done -> runA3(done) },
      { done -> runA4(done) },
      { done -> runA6(done) },
      { done -> runB1(done) },
      { done -> runC1(done) },
      { done -> runC2(done) },
      { done -> runC3(done) },
      { done -> runD1(done) },
      { done -> runD2(done) },
      { done -> runD3(done) },
      { done -> runD5(done) },
      { done -> runE1(done) },
      { done -> runE2(done) },
      { done -> runE3(done) }
    )

    Log.i(INFO_TAG, "[EVAL SUITE START] selected-scenarios=${selected.size}")
    runInOrder(selected)
  }

  private fun runInOrder(runs: List<(() -> Unit) -> Unit>, index: Int = 0) {
    if (index >= runs.size) {
      Log.i(INFO_TAG, "[EVAL SUITE END] All selected simulation scenarios completed.")
      return
    }

    runs[index] { runInOrder(runs, index + 1) }
  }
}