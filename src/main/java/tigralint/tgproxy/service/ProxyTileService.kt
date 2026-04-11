package tigralint.tgproxy.service

import android.content.Intent
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import tigralint.tgproxy.R

class ProxyTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        val isRunning = ProxyForegroundService.isRunning
        val intent = Intent(this, ProxyForegroundService::class.java)
        
        if (isRunning) {
            intent.action = ProxyForegroundService.ACTION_STOP
            startService(intent) // Will stop the service
        } else {
            intent.action = ProxyForegroundService.ACTION_START
            // Need startForegroundService for background start
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        }
        
        // Optimistically update, actual update will come from requestTileUpdate
        val tile = qsTile ?: return
        tile.state = Tile.STATE_UNAVAILABLE
        tile.updateTile()
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        val isRunning = ProxyForegroundService.isRunning
        
        if (isRunning) {
            tile.state = Tile.STATE_ACTIVE
            tile.label = "Tigre Proxy"
            tile.subtitle = if (tigralint.tgproxy.util.Texts.isRu) "Включен" else "Active"
        } else {
            tile.state = Tile.STATE_INACTIVE
            tile.label = "Tigre Proxy"
            tile.subtitle = if (tigralint.tgproxy.util.Texts.isRu) "Выключен" else "Stopped"
        }
        tile.updateTile()
    }
}
