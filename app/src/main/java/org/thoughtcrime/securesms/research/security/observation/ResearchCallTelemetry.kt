package org.thoughtcrime.securesms.research.security.observation

import android.os.SystemClock
import org.signal.core.util.logging.Log

// JVMstatic hooks for java-kotlin code
object ResearchCallTelemetry {

  @JvmStatic
  fun callStarted(callId: Long, isOutgoing: Boolean, peerId: String) {
    observe {
      CallStartedSecurityEvent(
        callId = callId,
        callDirection = if (isOutgoing) CallDirection.OUTGOING else CallDirection.INCOMING,
        peerId = peerId,
        observedAtMillis = SystemClock.elapsedRealtime()
      )
    }
  }

  @JvmStatic
  fun callAccepted(callId: Long, peerId: String) {
    observe {
      CallAcceptanceSecurityEvent(
        callId = callId,
        peerId = peerId,
        observedAtMillis = SystemClock.elapsedRealtime()
      )
    }
  }

  @JvmStatic
  fun audioTx(callId: Long, enabled: Boolean, peerId: String) {
    observe {
      MediaTxSecurityEvent(
        callId = callId,
        mediaKind = MediaKind.AUDIO,
        enabled = enabled,
        peerId = peerId,
        observedAtMillis = SystemClock.elapsedRealtime()
      )
    }
  }

  @JvmStatic
  fun videoTx(callId: Long, enabled: Boolean, peerId: String) {
    observe {
      MediaTxSecurityEvent(
        callId = callId,
        mediaKind = MediaKind.VIDEO,
        enabled = enabled,
        peerId = peerId,
        observedAtMillis = SystemClock.elapsedRealtime()
      )
    }
  }

  private inline fun observe(createEvent: () -> SecurityEvent) {
    try {
      SecurityTelemetryEngine.submitEvent(createEvent())
      //Log.i(INFO_TAG, "Call telemetry event complete")
    } catch (e: Exception) {
      Log.w(ERROR_TAG, "Call telemetry submission failed", e)
    }
  }
}