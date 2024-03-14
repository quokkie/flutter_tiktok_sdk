package com.k9i.flutter_tiktok_sdk

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.os.Bundle
import com.bytedance.sdk.open.tiktok.TikTokOpenApiFactory
import com.bytedance.sdk.open.tiktok.api.TikTokOpenApi
import com.bytedance.sdk.open.tiktok.authorize.model.Authorization
import com.bytedance.sdk.open.tiktok.common.handler.IApiEventHandler
import com.bytedance.sdk.open.tiktok.common.model.BaseReq
import com.bytedance.sdk.open.tiktok.common.model.BaseResp
import android.content.pm.PackageManager
import android.util.Log
import android.widget.Toast
import java.security.MessageDigest

// Activity receiving callbacks from TikTok Sdk
class TikTokEntryActivity : Activity(), IApiEventHandler {
    private lateinit var tikTokOpenApi: TikTokOpenApi

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val manager = packageManager
        var packageInfo: PackageInfo? = null
        try {
            packageInfo = manager.getPackageInfo("app.ramd.am", PackageManager.GET_SIGNATURES)
        } catch (e: PackageManager.NameNotFoundException) {
            Toast.makeText(this, "Error when getting signature" + e.localizedMessage, Toast.LENGTH_LONG).show()
            e.printStackTrace()
        }

        val signatures = packageInfo?.signatures
        val ss = signatures?.get(0)?.toByteArray()?.let { MD5.hexdigest(it) }
        val toastMessage = if (ss != null) {
            "signature $ss"
        } else {
            "No signature"
        }
        Log.e("TikTokLogin", toastMessage)
        Toast.makeText(this, toastMessage, Toast.LENGTH_LONG).show()

        val clipboardManager = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("signature", ss ?: "")
        clipboardManager.setPrimaryClip(clip)

        tikTokOpenApi = TikTokOpenApiFactory.create(this)
        tikTokOpenApi.handleIntent(intent, this)
    }

    override fun onReq(req: BaseReq) {
    }

    override fun onResp(resp: BaseResp) {
        if (resp is Authorization.Response) {
            val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
            if (launchIntent == null) {
                finish()
                return
            }
            launchIntent.putExtra(TIKTOK_LOGIN_RESULT_SUCCESS, resp.isSuccess)
            launchIntent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            if (resp.isSuccess) {
                launchIntent.putExtra(TIKTOK_LOGIN_RESULT_AUTH_CODE, resp.authCode)
                launchIntent.putExtra(TIKTOK_LOGIN_RESULT_STATE, resp.state)
                launchIntent.putExtra(TIKTOK_LOGIN_RESULT_GRANTED_PERMISSIONS, resp.grantedPermissions)
            } else {
                launchIntent.putExtra(TIKTOK_LOGIN_RESULT_CANCEL, resp.isCancel)
                launchIntent.putExtra(TIKTOK_LOGIN_RESULT_ERROR_CODE, resp.errorCode)
                launchIntent.putExtra(TIKTOK_LOGIN_RESULT_ERROR_MSG, resp.errorMsg)
            }
            startActivity(launchIntent)
            finish()
        } else {
            // TODO Video Kit Implementation
            finish()
        }
    }

    override fun onErrorIntent(intent: Intent) {
        finish()
    }

    companion object {
        const val TIKTOK_LOGIN_RESULT_SUCCESS = "TIKTOK_LOGIN_RESULT_SUCCESS"
        const val TIKTOK_LOGIN_RESULT_CANCEL = "TIKTOK_LOGIN_RESULT_CANCEL"
        const val TIKTOK_LOGIN_RESULT_AUTH_CODE = "TIKTOK_LOGIN_RESULT_AUTH_CODE"
        const val TIKTOK_LOGIN_RESULT_STATE = "TIKTOK_LOGIN_RESULT_STATE"
        const val TIKTOK_LOGIN_RESULT_GRANTED_PERMISSIONS = "TIKTOK_LOGIN_RESULT_GRANTED_PERMISSIONS"
        const val TIKTOK_LOGIN_RESULT_ERROR_CODE = "TIKTOK_LOGIN_RESULT_ERROR_CODE"
        const val TIKTOK_LOGIN_RESULT_ERROR_MSG = "TIKTOK_LOGIN_RESULT_ERROR_MSG"
    }

    object MD5 {
        private val hexDigits = charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')

        fun hexdigest(paramString: String): String? {
            return try {
                hexdigest(paramString.toByteArray())
            } catch (e: Exception) {
                null
            }
        }

        fun hexdigest(paramArrayOfByte: ByteArray): String? {
            return try {
                val localMessageDigest = MessageDigest.getInstance("MD5")
                localMessageDigest.update(paramArrayOfByte)
                val arrayOfByte = localMessageDigest.digest()
                val arrayOfChar = CharArray(32)
                var j = 0
                for (i in 0 until 16) {
                    val k = arrayOfByte[i].toInt()
                    arrayOfChar[j++] = hexDigits[k ushr 4 and 0xF]
                    arrayOfChar[j++] = hexDigits[k and 0xF]
                }
                String(arrayOfChar)
            } catch (e: Exception) {
                null
            }
        }
    }

}

object MD5 {
    private val hexDigits = charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')

    fun hexdigest(paramString: String): String? {
        return try {
            hexdigest(paramString.toByteArray())
        } catch (e: Exception) {
            null
        }
    }

    fun hexdigest(paramArrayOfByte: ByteArray): String? {
        return try {
            val localMessageDigest = MessageDigest.getInstance("MD5")
            localMessageDigest.update(paramArrayOfByte)
            val arrayOfByte = localMessageDigest.digest()
            val arrayOfChar = CharArray(32)
            var j = 0
            for (i in 0 until 16) {
                val k = arrayOfByte[i].toInt()
                arrayOfChar[j++] = hexDigits[k ushr 4 and 0xF]
                arrayOfChar[j++] = hexDigits[k and 0xF]
            }
            String(arrayOfChar)
        } catch (e: Exception) {
            null
        }
    }
}

