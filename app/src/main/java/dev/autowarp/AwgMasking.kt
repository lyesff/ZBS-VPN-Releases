package dev.autowarp

/** Changes only I1 for one explicit diagnostic run; never saves credentials. */
internal object AwgMasking {
    fun withI1(quick:String,signature:String):String {
        require(quick.length in 1..65536) { "awg_mask_invalid_config" }
        require(signature.matches(Regex("^<b 0x(?:[0-9a-fA-F]{2}){1,2048}>$"))) {
            "awg_mask_invalid_signature"
        }
        val rows=quick.replace("\r\n","\n").split('\n').toMutableList()
        var section=""
        var header=-1
        var existing=-1
        for(i in rows.indices){
            val line=rows[i].trim()
            if(line.startsWith("#") || line.startsWith(";"))continue
            if(line.startsWith("[")){
                section=line
                if(line=="[Interface]"){
                    require(header<0) { "awg_mask_duplicate_interface" }
                    header=i
                }
            }else if(section=="[Interface]" && line.substringBefore('=').trim()=="I1"){
                require(existing<0) { "awg_mask_duplicate_i1" }
                existing=i
            }
        }
        require(header>=0) { "awg_mask_missing_interface" }
        val replacement="I1 = $signature"
        if(existing>=0)rows[existing]=replacement else rows.add(header+1,replacement)
        return rows.joinToString("\n").also {
            require(it.length<=65536) { "awg_mask_config_too_large" }
        }
    }
}
