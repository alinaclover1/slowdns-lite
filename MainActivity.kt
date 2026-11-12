package id.slowdns.lite

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.Process
import android.text.InputType
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import core.Core

object K {
    const val START = "id.slowdns.lite.START"
    const val STOP = "id.slowdns.lite.STOP"
    const val STATUS = "id.slowdns.lite.STATUS"
    const val STATE = "id.slowdns.lite.STATE"
}

class MainActivity : Activity() {
    private lateinit var fDns: EditText
    private lateinit var fNs: EditText
    private lateinit var fKey: EditText
    private lateinit var fUser: EditText
    private lateinit var fPass: EditText
    private lateinit var typeSp: Spinner
    private lateinit var btn: Button
    private lateinit var status: TextView
    private var state = "idle"

    private val rx = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            setState(i.getStringExtra("state") ?: "idle", i.getStringExtra("msg") ?: "")
        }
    }

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        val p = getSharedPreferences("cfg", MODE_PRIVATE)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        val mp = ViewGroup.LayoutParams.MATCH_PARENT
        val wc = ViewGroup.LayoutParams.WRAP_CONTENT

        fun field(hint: String, key: String, pw: Boolean = false): EditText {
            val e = EditText(this)
            e.hint = hint
            e.setText(p.getString(key, ""))
            if (pw) e.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            else e.setSingleLine()
            col.addView(e, LinearLayout.LayoutParams(mp, wc))
            return e
        }

        fDns = field("DNS resolver (contoh 8.8.8.8)", "dns")
        fNs = field("NS (contoh ns-s1.example.com)", "ns")
        fKey = field("Kunci publik (hex)", "key")
        typeSp = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, arrayOf("TXT", "NULL"))
            setSelection(if (p.getString("type", "TXT") == "NULL") 1 else 0)
        }
        col.addView(typeSp, LinearLayout.LayoutParams(mp, wc))
        fUser = field("Nama pengguna SSH", "user")
        fPass = field("Kata sandi SSH", "pass", true)

        btn = Button(this)
        col.addView(btn, LinearLayout.LayoutParams(mp, wc))
        status = TextView(this).apply { setPadding(0, pad, 0, 0) }
        col.addView(status, LinearLayout.LayoutParams(mp, wc))
        setContentView(ScrollView(this).apply { addView(col) })
        setState("idle", "")

        btn.setOnClickListener {
            if (state == "idle") {
                if (fDns.text.isBlank() || fNs.text.isBlank() || fKey.text.isBlank() || fUser.text.isBlank()) {
                    Toast.makeText(this, "Lengkapi DNS, NS, kunci, dan user", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                p.edit()
                    .putString("dns", fDns.text.toString().trim())
                    .putString("ns", fNs.text.toString().trim())
                    .putString("key", fKey.text.toString().trim())
                    .putString("type", typeSp.selectedItem.toString())
                    .putString("user", fUser.text.toString().trim())
                    .putString("pass", fPass.text.toString())
                    .apply()
                val prep = VpnService.prepare(this)
                if (prep != null) startActivityForResult(prep, 1) else startVpn()
            } else {
                startService(Intent(this, VpnSvc::class.java).setAction(K.STOP))
            }
        }

        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 0)
        }
    }

    private fun startVpn() {
        val i = Intent(this, VpnSvc::class.java).setAction(K.START)
            .putExtra("dns", fDns.text.toString().trim())
            .putExtra("ns", fNs.text.toString().trim())
            .putExtra("key", fKey.text.toString().trim())
            .putExtra("type", typeSp.selectedItem.toString())
            .putExtra("user", fUser.text.toString().trim())
            .putExtra("pass", fPass.text.toString())
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i) else startService(i)
        setState("connecting", "")
    }

    override fun onActivityResult(req: Int, res: Int, data: Intent?) {
        if (req == 1 && res == RESULT_OK) startVpn()
    }

    override fun onResume() {
        super.onResume()
        val f = IntentFilter(K.STATE)
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(rx, f, Context.RECEIVER_NOT_EXPORTED)
        else registerReceiver(rx, f)
        try {
            startService(Intent(this, VpnSvc::class.java).setAction(K.STATUS))
        } catch (_: Exception) {
        }
    }

    override fun onPause() {
        super.onPause()
        try { unregisterReceiver(rx) } catch (_: Exception) {}
    }

    private fun setState(s: String, msg: String) {
        state = s
        status.text = when (s) {
            "connected" -> "Tersambung"
            "connecting" -> "Menyambung… (bisa sampai 1 menit)"
            else -> if (msg.isEmpty()) "Terputus" else "Terputus: $msg"
        }
        btn.text = if (s == "idle") "Sambung" else "Putus"
    }
}

// Berjalan di proses terpisah (:vpn). Saat putus, prosesnya dimatikan supaya inti Go bersih.
class VpnSvc : VpnService() {
    @Volatile private var busy = false
    @Volatile private var connected = false

    override fun onStartCommand(i: Intent?, flags: Int, startId: Int): Int {
        when (i?.action) {
            K.START -> if (!busy) {
                busy = true
                begin(i)
            }
            K.STOP -> shutdown("")
            K.STATUS -> if (busy) {
                send(if (connected) "connected" else "connecting", "")
            } else {
                send("idle", "")
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun begin(i: Intent) {
        startFg()
        Thread {
            try {
                send("connecting", "")
                Core.connect(
                    i.getStringExtra("dns") ?: "",
                    i.getStringExtra("ns") ?: "",
                    i.getStringExtra("key") ?: "",
                    i.getStringExtra("type") ?: "TXT",
                    i.getStringExtra("user") ?: "",
                    i.getStringExtra("pass") ?: "",
                    "8.8.8.8"
                )
                val b = Builder()
                    .setSession("SlowDNS Lite")
                    .setMtu(1500)
                    .addAddress("10.8.0.2", 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("8.8.8.8")
                // Aplikasi ini sendiri dikecualikan agar soket DNS/SSH tidak masuk VPN lagi.
                try { b.addDisallowedApplication(packageName) } catch (_: Exception) {}
                val tun: ParcelFileDescriptor = b.establish() ?: throw Exception("VPN ditolak")
                Core.startTun(tun.detachFd().toLong())
                connected = true
                send("connected", "")
                while (busy) {
                    Thread.sleep(3000)
                    if (!Core.alive()) throw Exception("Koneksi SSH terputus")
                }
            } catch (e: Throwable) {
                shutdown(e.message ?: "error")
            }
        }.start()
    }

    private fun startFg() {
        val nm = getSystemService(NotificationManager::class.java)
        val nb: Notification.Builder
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(NotificationChannel("vpn", "VPN", NotificationManager.IMPORTANCE_LOW))
            nb = Notification.Builder(this, "vpn")
        } else {
            nb = Notification.Builder(this)
        }
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        startForeground(
            1,
            nb.setContentTitle("SlowDNS Lite")
                .setContentText("VPN aktif")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(pi)
                .build()
        )
    }

    private fun send(s: String, m: String) {
        sendBroadcast(Intent(K.STATE).setPackage(packageName).putExtra("state", s).putExtra("msg", m))
    }

    private fun shutdown(msg: String) {
        busy = false
        send("idle", msg)
        try { stopForeground(true) } catch (_: Exception) {}
        Process.killProcess(Process.myPid())
    }

    override fun onRevoke() {
        shutdown("")
    }
}
