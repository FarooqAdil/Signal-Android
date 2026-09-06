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
      FrameworkConfig.Simulate.receiptOverload
    )

    MaterialAlertDialogBuilder(activity)
      .setTitle("Security Observation Config")
      .setMultiChoiceItems(labels, selected) { _, index, checked ->
        selected[index] = checked
      }
      .setNegativeButton("Cancel", null)
      .setPositiveButton("Apply") { _, _ ->
        applyConfig(selected)
      }.setOnDismissListener {
        dialogShowing = false
        Log.i(INFO_TAG, "Config dialog dismissed")
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
    FrameworkConfig.Simulate.receiptOverload = selected[6]

    Log.i(INFO_TAG, "Config applied")
  }
}