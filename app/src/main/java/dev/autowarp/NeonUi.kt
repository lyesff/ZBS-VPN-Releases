package dev.autowarp

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.sp
import kotlin.math.cos
import kotlin.math.sin

internal object Neon {
    val Green=Color(0xff16F59A)
    val Ice=Color(0xff87DAE9)
    val Background=Color(0xff040C14)
    val Surface=Color(0xff0B1822)
    val Muted=Color(0xff9BB3BE)
    val Error=Color(0xffFF7A8B)
}

@Composable internal fun NeonTheme(content:@Composable ()->Unit){
    MaterialTheme(colorScheme=darkColorScheme(
        primary=Neon.Green,onPrimary=Color(0xff002C1C),
        primaryContainer=Color(0xff064333),onPrimaryContainer=Color(0xffB6FFDB),
        secondary=Neon.Ice,onSecondary=Color(0xff002C34),
        background=Neon.Background,onBackground=Color(0xffEAF8F7),
        surface=Neon.Surface,onSurface=Color(0xffEAF8F7),
        surfaceVariant=Color(0xff10232C),onSurfaceVariant=Neon.Muted,
        surfaceDim=Neon.Background,surfaceBright=Color(0xff12342F),
        surfaceContainerLowest=Neon.Background,surfaceContainerLow=Color(0xff07141C),
        surfaceContainer=Color(0xff091B23),surfaceContainerHigh=Color(0xff0B2329),
        surfaceContainerHighest=Color(0xff0D2C2D),
        outline=Color(0xff46616C),outlineVariant=Color(0xff233D48),
        error=Neon.Error
    ),content=content)
}

@Composable internal fun NeonCard(modifier:Modifier=Modifier,content:@Composable ColumnScope.()->Unit){
    Card(modifier,shape=CutCornerShape(10.dp),border=BorderStroke(1.dp,Neon.Green.copy(alpha=.35f)),
        colors=CardDefaults.cardColors(containerColor=Neon.Background,contentColor=Color(0xffEAF8F7)),content=content)
}

/** Vector ornament, deliberately independent of the VPN state and engine. */
@Composable internal fun NeonSlashes(modifier:Modifier=Modifier,color:Color=Neon.Green){
    Canvas(modifier.size(58.dp,14.dp)){
        val unit=size.width/6f
        repeat(5){i->
            val x=i*unit
            val path=Path().apply{
                moveTo(x,size.height);lineTo(x+unit*.65f,size.height)
                lineTo(x+unit*1.55f,0f);lineTo(x+unit*.9f,0f);close()
            }
            drawPath(path,color.copy(alpha=1f-i*.18f))
        }
    }
}

@Composable internal fun NeonBrand(){
    Column(Modifier.fillMaxWidth().padding(top=4.dp,bottom=12.dp)){
        Row(verticalAlignment=Alignment.CenterVertically){
            Text(buildAnnotatedString{
                withStyle(SpanStyle(color=Color(0xffF0F8FA))){append("ZBS ")}
                withStyle(SpanStyle(color=Neon.Green)){append("VPN")}
            },fontSize=36.sp,fontWeight=FontWeight.Black,fontStyle=FontStyle.Italic,
                letterSpacing=1.sp,modifier=Modifier.weight(1f))
            NeonSlashes()
        }
        Text("ZERO BARRIERS SYSTEM",fontSize=10.sp,letterSpacing=2.8.sp,
            color=Color(0xffBDCFD5),fontStyle=FontStyle.Italic)
    }
}

private fun Modifier.neonFrame(color:Color)=drawBehind{
    val cut=12.dp.toPx().coerceAtMost(size.minDimension/3)
    val p=Path().apply{
        moveTo(cut,0f);lineTo(size.width-cut,0f);lineTo(size.width,cut)
        lineTo(size.width,size.height-cut);lineTo(size.width-cut,size.height)
        lineTo(cut,size.height);lineTo(0f,size.height-cut);lineTo(0f,cut);close()
    }
    drawPath(p,color.copy(alpha=.025f),style=Stroke(16.dp.toPx()))
    drawPath(p,color.copy(alpha=.05f),style=Stroke(8.dp.toPx()))
    drawPath(p,color.copy(alpha=.12f),style=Stroke(3.dp.toPx()))
}

@Composable internal fun NeonPanel(
    color:Color=Neon.Green,contentPadding:Dp=18.dp,spacing:Dp=14.dp,
    content:@Composable ColumnScope.()->Unit
){
    val shape=CutCornerShape(12.dp)
    Box(Modifier.fillMaxWidth().neonFrame(color)
        .background(Brush.linearGradient(listOf(Color(0xff072723),Neon.Surface,Neon.Background)),shape)
        .border(BorderStroke(1.2.dp,color.copy(alpha=.65f)),shape).clip(shape)){
        NeonSkyline(Modifier.align(Alignment.BottomEnd).fillMaxWidth(.58f).height(78.dp))
        Column(Modifier.fillMaxWidth().padding(contentPadding),verticalArrangement=Arrangement.spacedBy(spacing),content=content)
    }
}

@Composable private fun NeonSkyline(modifier:Modifier){
    Canvas(modifier){
        val widths=18
        val step=size.width/widths
        repeat(widths){i->
            val h=size.height*(.13f+((i*7+3)%11)/16f)
            val left=i*step
            val top=size.height-h
            drawRect(Color(0xff10243E).copy(alpha=.46f),Offset(left,top),Size(step*.72f,h))
            repeat(5){row->
                if(top+row*8.dp.toPx()<size.height-5.dp.toPx()){
                    val c=if((i+row)%3==0)Color(0xffB942F5) else Neon.Ice
                    drawRect(c.copy(alpha=.16f),Offset(left+step*.2f,top+4.dp.toPx()+row*8.dp.toPx()),Size(2.dp.toPx(),2.dp.toPx()))
                }
            }
        }
    }
}

internal enum class NeonGlyph { POWER, SHIELD, GLOBE, PROFILE, SETTINGS, MASK, DOWN, UP, PULSE, CLOCK, CHECK }

@Composable internal fun NeonSymbol(glyph:NeonGlyph,modifier:Modifier=Modifier,color:Color=Neon.Green){
    Canvas(modifier.size(24.dp)){
        val w=size.width;val h=size.height
        val stroke=Stroke(width=size.minDimension*.075f,cap=StrokeCap.Round)
        fun line(x1:Float,y1:Float,x2:Float,y2:Float)=drawLine(color,Offset(w*x1,h*y1),Offset(w*x2,h*y2),stroke.width,StrokeCap.Round)
        when(glyph){
            NeonGlyph.POWER->{drawArc(color,-55f,290f,false,Offset(w*.17f,h*.17f),Size(w*.66f,h*.66f),style=stroke);line(.5f,.08f,.5f,.45f)}
            NeonGlyph.CHECK->{drawCircle(color,radius=w*.4f,style=stroke);line(.29f,.5f,.44f,.65f);line(.44f,.65f,.73f,.34f)}
            NeonGlyph.GLOBE->{
                drawCircle(color,radius=w*.4f,style=stroke)
                drawOval(color,Offset(w*.32f,h*.1f),Size(w*.36f,h*.8f),style=stroke)
                line(.12f,.5f,.88f,.5f);line(.2f,.3f,.8f,.3f);line(.2f,.7f,.8f,.7f)
            }
            NeonGlyph.SHIELD->{
                val p=Path().apply{moveTo(w*.5f,h*.08f);lineTo(w*.84f,h*.23f);lineTo(w*.79f,h*.61f);quadraticBezierTo(w*.7f,h*.83f,w*.5f,h*.94f);quadraticBezierTo(w*.3f,h*.83f,w*.21f,h*.61f);lineTo(w*.16f,h*.23f);close()}
                drawPath(p,color,style=stroke)
            }
            NeonGlyph.PROFILE->{
                val p=Path().apply{moveTo(w*.5f,h*.12f);lineTo(w*.86f,h*.5f);lineTo(w*.5f,h*.88f);lineTo(w*.14f,h*.5f);close()}
                drawPath(p,color,style=stroke)
            }
            NeonGlyph.SETTINGS->{
                val p=Path()
                repeat(32){i->
                    val a=(i*2*Math.PI/32).toFloat()
                    val r=if(i%4 in 1..2).44f else .35f
                    val x=w*(.5f+r*cos(a));val y=h*(.5f+r*sin(a))
                    if(i==0)p.moveTo(x,y) else p.lineTo(x,y)
                };p.close();drawPath(p,color,style=stroke);drawCircle(color,radius=w*.14f,style=stroke)
            }
            NeonGlyph.MASK->{
                repeat(3){i->val y=.24f+i*.26f;val x=if(i==1).65f else .35f
                    line(.12f,y,x-.1f,y);line(x+.1f,y,.88f,y)
                    drawCircle(color,radius=w*.09f,center=Offset(w*x,h*y),style=stroke)
                }
            }
            NeonGlyph.DOWN,NeonGlyph.UP->{
                val down=glyph==NeonGlyph.DOWN
                val y=if(down).77f else .23f;val tail=if(down).2f else .8f;val end=if(down).55f else .45f
                line(.5f,tail,.5f,y);line(.28f,end,.5f,y);line(.72f,end,.5f,y)
            }
            NeonGlyph.PULSE->{
                val p=Path().apply{moveTo(0f,h*.55f);lineTo(w*.24f,h*.55f);lineTo(w*.38f,h*.2f);lineTo(w*.54f,h*.84f);lineTo(w*.68f,h*.42f);lineTo(w*.77f,h*.55f);lineTo(w,h*.55f)}
                drawPath(p,color,style=stroke)
            }
            NeonGlyph.CLOCK->{drawCircle(color,radius=w*.39f,style=stroke);line(.5f,.27f,.5f,.5f);line(.5f,.5f,.67f,.6f)}
        }
    }
}

@Composable internal fun NeonConnectButton(text:String,enabled:Boolean,onClick:()->Unit){
    val color=if(enabled)Neon.Green else Color(0xff537E74)
    val shape=RoundedCornerShape(50)
    Button(onClick=onClick,enabled=enabled,shape=shape,
        modifier=Modifier.fillMaxWidth().padding(vertical=10.dp).heightIn(min=72.dp)
            .drawBehind{
                val corner=CornerRadius(size.height/2)
                drawRoundRect(color.copy(alpha=.04f),cornerRadius=corner,style=Stroke(24.dp.toPx()))
                drawRoundRect(color.copy(alpha=.08f),cornerRadius=corner,style=Stroke(12.dp.toPx()))
                drawRoundRect(color.copy(alpha=.18f),cornerRadius=corner,style=Stroke(5.dp.toPx()))
            }.background(Brush.verticalGradient(listOf(Color(0xff106341),Color(0xff073A2E),Color(0xff05271F))),shape),
        colors=ButtonDefaults.buttonColors(containerColor=Color.Transparent,contentColor=Color(0xffE6FFF1),
            disabledContainerColor=Color.Transparent,disabledContentColor=Color(0xff8CA99F)),
        border=BorderStroke(1.5.dp,color),contentPadding=PaddingValues(horizontal=20.dp,vertical=16.dp)){
        NeonSymbol(NeonGlyph.POWER,Modifier.size(30.dp),color)
        Spacer(Modifier.width(12.dp))
        Text(text,fontSize=18.sp,fontWeight=FontWeight.Bold,letterSpacing=.5.sp,
            textAlign=androidx.compose.ui.text.style.TextAlign.Center)
    }
}

@Composable internal fun NeonControlRow(
    label:String,value:String,subtitle:String="",glyph:NeonGlyph=NeonGlyph.MASK,
    enabled:Boolean=true,onClick:()->Unit
){
    Surface(onClick=onClick,enabled=enabled,modifier=Modifier.fillMaxWidth(),
        shape=RoundedCornerShape(14.dp),color=Neon.Surface,
        border=BorderStroke(1.dp,if(enabled)Color(0xff48606C) else Color(0xff263B45))){
        Row(Modifier.padding(14.dp),verticalAlignment=Alignment.CenterVertically,
            horizontalArrangement=Arrangement.spacedBy(12.dp)){
            NeonSymbol(glyph,Modifier.size(26.dp),if(enabled)Neon.Green else Neon.Muted)
            Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(3.dp)){
                Text(label,fontWeight=FontWeight.SemiBold,fontSize=15.sp,color=Color(0xffDFECF0))
                if(subtitle.isNotBlank())Text(subtitle,fontSize=11.sp,lineHeight=15.sp,color=Neon.Muted)
            }
            if(value.isNotBlank())Surface(shape=RoundedCornerShape(20.dp),
                color=Color(0xff102A30),border=BorderStroke(.7.dp,Color(0xff3F6269))){
                Text(value,Modifier.padding(horizontal=10.dp,vertical=6.dp).widthIn(max=112.dp),
                    fontSize=12.sp,color=if(enabled)Color(0xffC5FBE5) else Neon.Muted,maxLines=1,overflow=TextOverflow.Ellipsis)
            }
            Text("›",fontSize=24.sp,color=if(enabled)Neon.Ice else Neon.Muted)
        }
    }
}

@Composable internal fun NeonStatusStrip(connected:Boolean){
    Surface(Modifier.fillMaxWidth(),shape=RoundedCornerShape(12.dp),
        color=Color(0xff06231E),border=BorderStroke(1.dp,Neon.Green.copy(alpha=.4f))){
        Row(Modifier.padding(horizontal=14.dp,vertical=12.dp),verticalAlignment=Alignment.CenterVertically,
            horizontalArrangement=Arrangement.spacedBy(12.dp)){
            NeonSymbol(if(connected)NeonGlyph.CHECK else NeonGlyph.SHIELD,Modifier.size(20.dp))
            Text(if(connected)"WARP ПОДТВЕРЖДЁН · ВСЁ ZBS!" else "ZERO BARRIERS SYSTEM",
                Modifier.weight(1f),fontSize=11.sp,fontWeight=FontWeight.Bold,letterSpacing=.7.sp,color=Neon.Green)
            NeonSlashes(Modifier.width(36.dp).height(10.dp))
        }
    }
}

@Composable internal fun NeonNavigationBar(tab:Int,onSelect:(Int)->Unit){
    NavigationBar(containerColor=Color(0xff06121B),modifier=Modifier.border(1.dp,Color(0xff173D40))){
        listOf(0 to "VPN",1 to "Профиль",3 to "Настройки").forEach{(index,label)->
            val selected=index==tab || (index==3 && tab==2)
            NavigationBarItem(selected=selected,onClick={onSelect(index)},
                icon={NeonSymbol(when(index){0->NeonGlyph.POWER;1->NeonGlyph.PROFILE;else->NeonGlyph.SETTINGS},
                    Modifier.size(26.dp),if(selected)Neon.Green else Neon.Ice)},
                label={Text(label)},colors=NavigationBarItemDefaults.colors(
                    selectedIconColor=Neon.Green,selectedTextColor=Neon.Green,
                    unselectedIconColor=Neon.Ice,unselectedTextColor=Neon.Muted,
                    indicatorColor=Color(0xff07513C)))
        }
    }
}
