package com.westone.testdemo;

import android.content.Context;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.GridLayout;
import android.widget.GridView;
import android.widget.TextView;

import com.westone.csmmanager.R;

import java.util.List;

class GridViewFuncAdapter extends ArrayAdapter {
    int id = 0;

    public GridViewFuncAdapter(Context context, int id, List list){
        super(context,id,list);
        this.id = id;
    }

    @Override
    public View getView(int position, View convertView,ViewGroup parent) {
        View view = LayoutInflater.from(getContext()).inflate(id,null);
        String item = (String) getItem(position);
        TextView textView = view.findViewById(R.id.item);
        if(null != item){
            textView.setText(item);
        }

        textView.setGravity(Gravity.CENTER);
        return view;
    }

}
