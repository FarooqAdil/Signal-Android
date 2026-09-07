package org.thoughtcrime.securesms.research.security.observation

import android.app.Activity
import org.signal.core.util.logging.Log
import com.google.android.material.dialog.MaterialAlertDialogBuilder

// TODO: File and object description
internal object FrameworkConfigDialog {

  private var dialogShowing = false

  private val labels = arrayOf(
    "[PROD] Observe security telemetry",
    "[PROD] Show security alerts",
    "[PROD] Report security alerts",
    "[PROD] Report suspicious users",
    "[PROD] Share security logs",
    "[PROD] Share security-relevant events",
    "[DEV] Show negative findings",
    "[DEV] Fire framework self-test (20s)",
    "[SIM] Simulate receipt overload"
  )

  // Build and show the dialog
  fun show(activity: Activity) {
    if (dialogShowing) {
      return
    }
    Log.i(INFO_TAG, "Showing dialog...")
    val selected = booleanArrayOf(
      FrameworkConfig.Production.observeSecurityTelemetry,
      FrameworkConfig.Production.showSecurityAlerts,
      FrameworkConfig.Production.basicReporting,
      FrameworkConfig.Production.reportUsers,
      FrameworkConfig.Production.shareLogs,
      FrameworkConfig.Production.shareFullTelemetry,
      FrameworkConfig.Development.showNegativeFindings,
      false,
      FrameworkConfig.Simulate.receiptOverload
    )

    MaterialAlertDialogBuilder(activity)
      .setTitle("Security Observation Config")
      .setMultiChoiceItems(labels, selected) { _, index, checked ->
        selected[index] = checked
      }
      .setNeutralButton("RESTART Signal Process") { _, _ -> 
        Log.i(INFO_TAG, "Restart Signal process requested") 
        SecurityTelemetryEngine.clearFrameworkAndRestartSignal(activity)
      }
      .setNegativeButton("Cancel", null)
      .setPositiveButton("Apply") { _, _ ->
        applyConfig(selected)
      }.setOnDismissListener {
        dialogShowing = false
        Log.i(INFO_TAG, "Config dialog dismissed")
        onFrameworkConfigDismissed(activity)
      }
      .show()
    Log.i(INFO_TAG, "Dialog shown")
    dialogShowing = true
  }

  // Updates the framework config on selecting apply
  private fun applyConfig(selected: BooleanArray) {
    FrameworkConfig.Production.observeSecurityTelemetry = selected[0]
    FrameworkConfig.Production.showSecurityAlerts = selected[1]
    FrameworkConfig.Production.basicReporting = selected[2]
    FrameworkConfig.Production.reportUsers = selected[3]
    FrameworkConfig.Production.shareLogs = selected[4]
    FrameworkConfig.Production.shareFullTelemetry = selected[5]
    FrameworkConfig.Development.showNegativeFindings = selected[6]
    if (selected[7]) {
      Log.i(INFO_TAG, "Framework self-test requested from config dialog")
      SecuritySimulationController.fireSelfTest()
    }
    FrameworkConfig.Simulate.receiptOverload = selected[8]

    Log.i(INFO_TAG, "Config applied")
  }
  
  // Is the dialog currently showing
  fun isShowing(): Boolean {
    return dialogShowing
  }
}