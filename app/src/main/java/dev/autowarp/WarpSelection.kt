package dev.autowarp

import org.json.JSONObject

/**
 * Probe scheduling is deliberately bounded: each live probe has a seven-second
 * deadline, and startup has a 60-second deadline.
 * Prior health only changes candidate ordering; it never proves connectivity.
 */
internal fun warpProbeOrder(
    routes:List<Route>, active:Route, health:JSONObject, initial:Boolean,
    cursor:Int, limit:Int=6
):List<Route> {
    val available=routes.distinctBy(Route::tag)
    val warpOnly=available.filter(Route::warp)
    val others=available.filterNot(Route::warp)
    fun recentSuccess(r:Route):Boolean {
        val h=health.optJSONObject(r.tag) ?: return false
        val age=System.currentTimeMillis()-h.optLong("at",0L)
        return age>=0L && age<=3_600_000L && h.optLong("ms",-1L)>=0L
    }
    val prioritized=warpOnly.sortedWith(compareByDescending<Route>(::recentSuccess)
        .thenBy { health.optJSONObject(it.tag)?.optLong("ms",Long.MAX_VALUE) ?: Long.MAX_VALUE })
    val result=linkedSetOf<Route>()
    result.add(active)
    if(initial) {
        // Probe all six standard WARP endpoint candidates, not just four.
        for(r in prioritized)if(result.size<limit)result.add(r)
        if(warpOnly.isEmpty()) {
            for(r in others)if(result.size<limit)result.add(r)
        } else {
            // On mixed routes, keep at least one proxy candidate if space.
            for(r in others)if(result.size<limit)result.add(r)
        }
    } else {
        val rotating=if(available.isEmpty())emptyList() else
            (0 until minOf(limit,available.size)).map { available[(cursor+it)%available.size] }
        for(r in prioritized.take(2)+rotating)if(result.size<limit)result.add(r)
    }
    return result.toList()
}

internal fun warpHealthScore(history:JSONObject?,stable:Boolean):Double {
    val arr=history?.optJSONArray("history") ?: return Double.POSITIVE_INFINITY
    if(arr.length()==0)return Double.POSITIVE_INFINITY
    val values=(0 until arr.length()).map { arr.optDouble(it,-1.0) }
    val good=values.filter {it>=0 && it.isFinite()}
    if(good.isEmpty())return Double.POSITIVE_INFINITY
    return good.average() + (values.size-good.size)*(if(stable)1800.0 else 150.0)/values.size
}
