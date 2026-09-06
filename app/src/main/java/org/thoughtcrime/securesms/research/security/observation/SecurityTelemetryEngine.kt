package org.thoughtcrime.securesms.research.security.observation

import org.signal.core.util.logging.Log

import java.util.concurrent.atomic.AtomicBoolean


// Module-wide val/vars
const val INFO_TAG = "SecurityTelemetry INFO"
const val FINDING_TAG = "SecurityTelemetry FINDING"
const val NEGATIVE_FINDING_TAG = "SecurityTelemetry NEGATIVE FINDING"
const val ERROR_TAG = "SecurityTelemetry ERROR"


// TODO: File and object description
object SecurityTelemetryEngine {

  private val initialized = AtomicBoolean(false)
  private val configDialogPending = AtomicBoolean(false)

  // Called once during app startup; initializes the framework
  fun initialize() {
    // init

    //Production demo mode:
    FrameworkConfig.productionDemo()

    initialized.set(true)
    Log.i(INFO_TAG, "Security telemetry engine initialized")
  }

  // Runs when the app enters the foreground (i.e. when it is returned to)
  // Sets flag to show config dialog
  fun onAppForegrounded() {
    if (initialized.get()) {
      configDialogPending.set(true)
      Log.i(INFO_TAG, "Config flag set due to app in foreground")
    } else {
      Log.i(INFO_TAG, "Config flag NOT set as app not initialized yet")
    }
  }

  // Returns true if a config dialog is pending and the framework is initialized
  // Lowers flag to show config dialog
  fun consumePendingConfigDialog(): Boolean {
    if (initialized.get() && configDialogPending.getAndSet(false)) {
      Log.i(INFO_TAG, "Config flag consumed")
      return true
    }
    Log.i(INFO_TAG, "Config flag not consumed. Initialized: " + initialized.get() + ", Dialog Pending: " + configDialogPending.get())
    return false
  }
}