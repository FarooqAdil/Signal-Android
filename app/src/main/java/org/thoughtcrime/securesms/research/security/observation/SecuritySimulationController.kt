package org.thoughtcrime.securesms.research.security.observation

import android.os.Handler
import android.os.Looper
import org.signal.core.util.logging.Log

// Controller for framework self-tests and later incident simulations
internal object SecuritySimulationController {

  private const val SELF_TEST_DELAY_MS = 20_000L

  private val handler = Handler(Looper.getMainLooper())

  // Schedules one generic framework self-test event
  fun fireSelfTest() {
    val requestedAt = System.currentTimeMillis()

    Log.i(INFO_TAG, "Framework self-test scheduled for ${SELF_TEST_DELAY_MS}ms delay at $requestedAt")

    handler.postDelayed({
      val firedAt = System.currentTimeMillis()

      Log.i(INFO_TAG, "Framework self-test event firing at $firedAt; requested at $requestedAt")

      SecurityTelemetryEngine.submitEvent(
          DevTestSecurityEvent(requestedAtMillis = requestedAt, firedAtMillis = firedAt))
    }, SELF_TEST_DELAY_MS)
  }
}