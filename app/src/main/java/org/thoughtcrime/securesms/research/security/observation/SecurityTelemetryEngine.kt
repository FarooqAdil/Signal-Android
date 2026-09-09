package org.thoughtcrime.securesms.research.security.observation

import org.signal.core.util.logging.Log
import org.signal.core.util.AppUtil

import android.content.Context
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
  private val appInForeground = AtomicBoolean(false)
  
  private val detectors = mutableListOf<SecurityDetector>()
  
  private lateinit var applicationContext: Context

  // Called once during app startup; initializes the framework
  fun initialize(context: Context) {
    // init
    applicationContext = context.applicationContext
    
    // Register Detectors
    detectors.add(DevTestDetector)
    detectors.add(ReceiptRateDetector)
    detectors.add(MediaConsentDetector)
    Log.i(INFO_TAG, "Detector registration complete: ${detectors.size} detector(s)")
    
    //Production demo mode:
    FrameworkConfig.productionDemo()

    initialized.set(true)
    Log.i(INFO_TAG, "Security telemetry engine initialized")
  }

  // Runs when the app enters the foreground (i.e. when it is returned to)
  // Sets flag to show config dialog
  fun onAppForegrounded() {
    appInForeground.set(true)
    
    if (initialized.get()) {
      configDialogPending.set(true)
      Log.i(INFO_TAG, "Config flag set due to app in foreground")
    } else {
      Log.i(INFO_TAG, "Config flag NOT set as app not initialized yet")
    }
  }
  
  // called when app backgrounded
  fun onAppBackgrounded() {
    appInForeground.set(false)
    Log.i(INFO_TAG, "Application entered background")
  }
  
  // returns whether the app is foregrounded
  fun isAppInForeground(): Boolean {
    return appInForeground.get()
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
  
  // Clears framework-owned process state and then calls for Signal restart
  fun clearFrameworkAndRestartSignal(context: Context) {
    Log.i(INFO_TAG, "Framework preparing to restart Signal process")

    // Detector and privacy-sensitive state cleanup:
    detectors.forEach{
      it.clear()
    }
    clearFindingPresentationState()
    
    Log.i(INFO_TAG, "Detectors and Findings cleared")

    Log.i(INFO_TAG, "Framework calling for restart")
    AppUtil.restart(context.applicationContext)
  }
  
  fun getApplicationContext(): Context {
    return applicationContext
  }
  
  // ***************************
  // Event and Detector Handling
  // ***************************
  
  // handles submitted events; forwards to detectors; forwards returned findings
  internal fun submitEvent(event: SecurityEvent) {
    if (!FrameworkConfig.Production.observeSecurityTelemetry) {
      return
    }
    
    Log.i(INFO_TAG, "Security engine received event")

    detectors
      .filter {
        event.type in it.accepts // filters detectors that accept the given event type
      } 
      .flatMap {
        it.process(event) // forwards the event to all accepting detectors and compiles returned findings
      } 
      .forEach {
        handleFinding(it) // handles each finding
      }  
  }
  
  // Checks config and if appropriate enqueues finding for presentation
  private fun handleFinding(finding: SecurityFinding) {
    val logTag = if (finding.type == FindingType.POSITIVE) FINDING_TAG else NEGATIVE_FINDING_TAG
    Log.i(logTag, "Finding generated: ${finding.findingId.take(7)} - ${finding.detectorId}")

    if (FrameworkConfig.Production.showSecurityAlerts && (finding.type == FindingType.POSITIVE ||
      (finding.type == FindingType.NEGATIVE && FrameworkConfig.Development.showNegativeFindings))) {
        enqueue(finding)
    }
  }
}