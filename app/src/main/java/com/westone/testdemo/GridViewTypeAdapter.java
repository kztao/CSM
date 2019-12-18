package com.westone.testdemo;

import android.content.Context;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import com.westone.csmmanager.R;

import java.util.List;

class GridViewTypeAdapter extends ArrayAdapter {
    private int id;

    public GridViewTypeAdapter(Context context, int resId, List list){
        super(context,resId,list);
        this.id = resId;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View view = LayoutInflater.from(getContext()).inflate(id,null);
        String item = (String) getItem(position);
        TextView textView = view.findViewById(R.id.type);
        if(null != item){
            textView.setText(item);
        }

        textView.setGravity(Gravity.CENTER);
        return view;
    }
}
