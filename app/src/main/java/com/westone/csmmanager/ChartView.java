package com.westone.csmmanager;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Point;
import android.graphics.Rect;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;

class ChartView extends View {
    private boolean minFlg = false;

    private float XSrc = 0.0f;
    private float XDst = 0.0f;
    private float YSrc = 0.0f;
    private float YDst = 0.0f;

    private float XP = 0.0f;
    private float YP = 0.0f;

    private long max  = 0,min = 0,ave = 0;


 //   private Path path = new Path();
    private Paint paintXText = new Paint();
    private Paint paintData = new Paint();

    private Paint paintMax = new Paint();
    private Paint paintMin = new Paint();
    private Paint paintAve = new Paint();

    private long[] timesData = null;

    public ChartView(Context context, AttributeSet attributeSet){
        super(context,attributeSet);
    }

    private void DrawXY(Canvas canvas){
        if(this.timesData == null){
            return;
        }

        String text = "性能耗能测试";
        Rect rect = new Rect();

        paintXText.setColor(Color.BLUE);
        paintXText.setAntiAlias(true);
        paintXText.setTextSize(40.0f);
        paintXText.setLinearText(true);
        paintXText.getTextBounds(text,0,text.length(),rect);

        XSrc = 100.0f;
        XDst = getWidth() - 50.0f;

        YSrc = 50.0f;
        YDst = getHeight() - paintXText.getTextSize() - 50.0f;

        canvas.drawText("性能耗能测试",(getWidth() - rect.width()) / 2,getHeight() - paintXText.getTextSize(),paintXText);
        canvas.drawLine(XSrc,YDst,XDst,YDst,paintXText);
        canvas.drawLine(XSrc,YSrc,XSrc,YDst,paintXText);
    }


    private void DrawData(Canvas canvas){
        if(timesData == null){
            return;
        }

        max = 0; min = 0; ave = 0;
        minFlg = false;

        for(int i = 0 ; i < timesData.length;i++){
            if(minFlg == false){
                min = timesData[i];
                minFlg = true;
            }

            if(timesData[i] > max){
                max = timesData[i];
            }

            if(timesData[i] < min){
                min = timesData[i];
            }

            ave += timesData[i];
        }

        Log.i("csm_testApp","sum = " + ave + ",num = " + timesData.length);
        ave /= timesData.length;

        XP = (XDst - XSrc) / timesData.length;
        if(max!=0){
            YP = (YDst - YSrc) / max;
        }

        paintData.setAntiAlias(true);

        float xb,xa,yb,ya;

        xb = XSrc;
        yb = YDst - (YP * timesData[0]);



        for(int i = 1; i < timesData.length;i++){
            paintData.setColor(Color.BLACK);
            canvas.drawCircle(xb,yb,XP * 0.05f,paintData);
            xa = xb + XP;
            ya = YDst - (YP * timesData[i]);

            paintData.setColor(Color.MAGENTA);
            canvas.drawLine(
                    xb,yb,xa,ya,paintData);
            xb = xa;
            yb = ya;
        }

        paintData.setColor(Color.BLACK);
        canvas.drawCircle(xb,yb,XP * 0.05f,paintData);
    }

    private void DrawAve(Canvas canvas){
        if(timesData == null){
            return;
        }
        paintAve.setTextSize(40.0f);
        paintAve.setColor(Color.RED);
        //canvas.drawLine(XSrc,YDst - (YP * ave),XDst,YDst - (YP * ave),paintAve);
        canvas.drawText("Ave = " + ave,0.0f,YDst - (YP * ave),paintAve);
    }

    private void DrawMax(Canvas canvas){
        if(timesData == null){
            return;
        }

        paintMax.setTextSize(40.0f);
        paintMax.setColor(Color.GREEN);
        //canvas.drawLine(XSrc,YSrc,XDst,YSrc,paintMax);
        canvas.drawText("Max = " + max,0.0f,YSrc,paintMax);
    }

    private void DrawMin(Canvas canvas){
        if(timesData == null){
            return;
        }

        paintMin.setTextSize(40.0f);
        paintMin.setColor(Color.BLACK);
        //canvas.drawLine(XSrc,YDst - (YP * min),XDst,YDst - (YP * min),paintMin);
        canvas.drawText("Min = " + min,0.0f,YDst - (YP * min),paintMin);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        DrawXY(canvas);
        DrawData(canvas);
        DrawMax(canvas);
        DrawMin(canvas);
        DrawAve(canvas);

    }

    public void InitData(long[] timesData){
        if(null == timesData){
            return;
        }
        this.timesData = timesData;
    }


    public void fresh(){
        requestLayout();
    }
}
