package org.thoughtcrime.securesms.research.security.observation

import org.signal.core.util.logging.Log

import android.app.Activity
import com.google.android.material.dialog.MaterialAlertDialogBuilder

import java.util.concurrent.ConcurrentLinkedQueue
import java.lang.ref.WeakReference

import android.Manifest
import android.app.PendingIntent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import org.signal.core.util.PendingIntentFlags
import org.thoughtcrime.securesms.R
import org.thoughtcrime.securesms.notifications.NotificationChannels
import org.signal.core.util.ServiceUtil
import android.os.Build

private const val SECURITY_FINDING_NOTIFICATION_ID = 1907
private var foregroundActivity = WeakReference<Activity>(null)
private var dialogShowing = false

// Process-lifetime queue for security findings awaiting presentation
internal object SecurityFindingQueue {

  private val findings = ConcurrentLinkedQueue<SecurityFinding>()

  fun add(finding: SecurityFinding) {
    findings.add(finding)
  }

  fun next(): SecurityFinding? {
    return findings.poll()
  }

  fun size(): Int {
    return findings.size
  }

  fun clear() {
    findings.clear()
  }

  fun isEmpty(): Boolean {
    return findings.isEmpty()
  }
}

// Enqueues a security finding, preparing it for presentation
internal fun enqueue(finding: SecurityFinding) {
  SecurityFindingQueue.add(finding)
  Log.i(INFO_TAG, "Security finding queued: ${finding.findingId.take(7)}. Queue size: ${SecurityFindingQueue.size()}")

  if (!SecurityTelemetryEngine.isAppInForeground()) {
    showBackgroundNotification(finding)
    return
  }
  
  val activity = foregroundActivity.get()

  if (activity != null && SecurityTelemetryEngine.isAppInForeground()) {
    activity.runOnUiThread { 
      if (!dialogShowing && !FrameworkConfigDialog.isShowing() && SecurityTelemetryEngine.isAppInForeground()) {
        showNext(activity)
      }
    }
  }
}

// Prepares to show the next finding
private fun showNext(activity: Activity) {
  if (!isCurrentActivity(activity) || FrameworkConfigDialog.isShowing() || dialogShowing) {
    return
  }
  
  val finding = SecurityFindingQueue.next() ?: return
  Log.i(INFO_TAG, "Attempting to show security finding: ${finding.findingId.take(7)}")
  showFinding(activity, finding)
}

// Shows a security finding
private fun showFinding(activity: Activity, finding: SecurityFinding) {
  val queuedFindings = SecurityFindingQueue.size()
  var closeAllRequested = false
    
    
  val actions = if (finding.possibleActions.isEmpty()) {
    "None"
  } else {
    finding.possibleActions.joinToString(", ")
  }

  val dialogTitle: String
  val logTag: String
  val findingLabel: String

  when (finding.type) {
    FindingType.POSITIVE -> {
      dialogTitle = "Security Incident Detected"
      logTag = FINDING_TAG
      findingLabel = "Positive"
    }
    FindingType.NEGATIVE -> {
      dialogTitle = "No Security Incident Detected"
      logTag = NEGATIVE_FINDING_TAG
      findingLabel = "Negative"
    }
  }

  val dialogBuilder = MaterialAlertDialogBuilder(activity)
    .setTitle("$dialogTitle [${finding.findingId.take(7)}]")
    .setMessage(
      "${finding.title}\n\n" +
      "${finding.explanation}\n\n" +
      "Detection at time ${finding.observationTime}\n\n" +
      "[Available Actions:]\n${actions}\n\n" +
      "[Developer Details:]\n${finding.developerDetails}"
    )
    .setPositiveButton("Close") { _, _ ->
      Log.i(logTag, "$findingLabel finding dismissed: " +
              "${finding.title}: ${finding.findingId.take(7)} - ${finding.detectorId}")
    }
    .setOnDismissListener {
      dialogShowing = false
      
      if (isCurrentActivity(activity)) {
        if (SecurityTelemetryEngine.consumePendingConfigDialog()) {
          Log.i(INFO_TAG, "Showing pending config dialog after security finding")
          FrameworkConfigDialog.show(activity)
        } else if (!closeAllRequested) {
          showNext(activity)
        }
      }
    }
  
  if (queuedFindings > 0) {
    dialogBuilder.setNeutralButton("Close all (${queuedFindings+1})") { _, _ ->
      closeAllRequested = true
      
      Log.i(logTag, "$findingLabel finding dismissed by Close all: " +
        "${finding.title}: ${finding.findingId.take(7)} - ${finding.detectorId}")
      
      SecurityFindingQueue.clear()
      
      Log.i(INFO_TAG, "Closed all cleared ${queuedFindings} queued finding(s); " +
        "${queuedFindings+1} finding(s) closed in total")
    }
  }

  dialogBuilder.show()
  
  dialogShowing = true

  Log.i(logTag, "$findingLabel finding shown: " +
          "${finding.title}: ${finding.findingId.take(7)} - ${finding.detectorId}")
}

// returns whether the security dialog is showing
fun isFindingDialogShowing(): Boolean {
  return dialogShowing
}

// returns whether the given activity is the current foreground activity
private fun isCurrentActivity(activity: Activity): Boolean {
  return foregroundActivity.get() === activity && !activity.isFinishing && 
    !activity.isDestroyed && SecurityTelemetryEngine.isAppInForeground()
}

// Provides a resumed Activity and presents any queued findings
fun onActivityResumed(activity: Activity) {
  foregroundActivity = WeakReference(activity)
  
  ServiceUtil
    .getNotificationManager(SecurityTelemetryEngine.getApplicationContext())
    .cancel(SECURITY_FINDING_NOTIFICATION_ID)
  
  if (!dialogShowing && !FrameworkConfigDialog.isShowing() && !SecurityFindingQueue.isEmpty()) {
    showNext(activity)
  }
}

// Removes the Activity reference when it is no longer resumed
fun onActivityPaused(activity: Activity) {
  if (foregroundActivity.get() === activity) {
    foregroundActivity.clear()
  }
}

// Shows the next finding when config dialog dismissed
fun onFrameworkConfigDismissed(activity: Activity) {
  if (isCurrentActivity(activity) && !dialogShowing && !SecurityFindingQueue.isEmpty()) {
    showNext(activity)
  }
}



// Shows a generic notification when a security finding occurs in the background
private fun showBackgroundNotification(finding: SecurityFinding) {
  val context = SecurityTelemetryEngine.getApplicationContext()

  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU 
      && ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
    Log.i(INFO_TAG, "Security finding notification skipped: notification permission unavailable")
    return
  }

  val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return

  val pendingIntent = PendingIntent.getActivity(context, 0, launchIntent, PendingIntentFlags.updateCurrent())

  val notification = NotificationCompat.Builder(context, NotificationChannels.getInstance().APP_ALERTS)
    .setSmallIcon(R.drawable.ic_notification)
    .setContentTitle("Security observation available: ${finding.detectorId}")
    .setContentText("Open Signal to review a security finding. \n [${finding.findingId.take(7)}] ${finding.title}")
    .setContentIntent(pendingIntent)
    .setAutoCancel(true)
    .build()

  ServiceUtil.getNotificationManager(context)
    .notify(SECURITY_FINDING_NOTIFICATION_ID, notification)

  Log.i(INFO_TAG, "Background security finding notification posted: ${finding.findingId.take(7)}")
}

// clears finding queue and notifications
internal fun clearFindingPresentationState() {
  SecurityFindingQueue.clear()

  ServiceUtil.getNotificationManager(SecurityTelemetryEngine.getApplicationContext())
    .cancel(SECURITY_FINDING_NOTIFICATION_ID)

  foregroundActivity.clear()

  Log.i(INFO_TAG, "Finding queue and notification cleared")
}