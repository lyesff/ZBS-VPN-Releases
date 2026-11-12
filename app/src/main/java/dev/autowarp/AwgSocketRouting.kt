package dev.autowarp

/** Binding and protection must both succeed; never fall back to unprotected UDP. */
internal fun awgBindAndProtect(bind:()->Unit,protect:()->Boolean):Boolean = try {
    bind()
    protect()
}catch(_:Exception){false}
