package org.thoughtcrime.securesms.research.security.observation

import org.signal.core.util.logging.Log


// TODO: File and object description
internal object FrameworkConfig {

  // Initialized with defaults for production
  internal object Production {
    internal var observeSecurityTelemetry = false // observe telemetry
    //internal var alwaysShowDialogOnForeground = true
    internal var showSecurityAlerts = false // show security alerts to users

    // Sharing & Reporting:
    internal var basicReporting = false // report security incidents to Signal
    internal var reportUsers = false // report other users causing security incidents to Signal
    internal var shareLogs = false // share all framework logs with Signal
    internal var shareFullTelemetry = false // share all security telemetry with Signal

  }
  
  // Initialized with defaults for dev purposes
  internal object Development {
    internal var showNegativeFindings = false
  }

  // Initialized with defaults
  internal object Simulate {
    internal var receiptOverload = false
    internal var shareAudio = false
    internal var shareVideo = false
  }

  // Sets vars with defaults for demoing (reduces workload)
  fun productionDemo() {
    Production.observeSecurityTelemetry = true
    Production.showSecurityAlerts = true
    Development.showNegativeFindings = true //temp
    //Production.basicReporting = true
    Log.i(INFO_TAG, "Demo config defaults set")
  }
}