package dev.autowarp

internal data class AwgTransferRate(val download:Long,val upload:Long)

/** Cumulative inner-IP bytes -> bytes/second, using actual monotonic elapsed time. */
internal class AwgTrafficMeter {
    private var previousDownload:Long?=null
    private var previousUpload=0L
    private var previousAt=0L

    fun sample(raw:String,nowMs:Long):AwgTransferRate? {
        val fields=raw.split(',')
        if(fields.size!=2 || nowMs<0)return null
        val download=fields[0].toLongOrNull()?.takeIf {it>=0} ?: return null
        val upload=fields[1].toLongOrNull()?.takeIf {it>=0} ?: return null
        val oldDownload=previousDownload
        val oldUpload=previousUpload
        val elapsed=nowMs-previousAt
        previousDownload=download
        previousUpload=upload
        previousAt=nowMs
        if(oldDownload==null || elapsed<=0 || download<oldDownload || upload<oldUpload)
            return AwgTransferRate(0,0)
        fun rate(delta:Long)=(delta.toDouble()*1000.0/elapsed.toDouble()).toLong()
        return AwgTransferRate(rate(download-oldDownload),rate(upload-oldUpload))
    }
}
