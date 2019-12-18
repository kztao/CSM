package com.westone.skflist;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.ListView;
import android.widget.Spinner;
import android.widget.TextView;

import com.westone.csmmanager.R;

public class SkfListActivity extends AppCompatActivity {

    ListView listView = null;
    Spinner spinner = null;
    TextView textViewCall = null;
    TextView textViewResult = null;
    Button button = null;
    BaseAdapter baseAdapter = null;

    String funcName = "null function";
    int devNamePosition = 0;
    int appNamePosition = 0;
    int containerNamePosition = 0;
    int filePosition = 0;

    int funcPosition = 0;
    int devPosition = 0;
    int appPosition = 0;
    int containerPosition = 0;
    int handlePosition = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_skf_list);

        listView = findViewById(R.id.skf_list_view);
        spinner = findViewById(R.id.skf_func_list);
        textViewCall = findViewById(R.id.callDesc);
        textViewResult = findViewById(R.id.skf_result);
        button = findViewById(R.id.skf_run);
        SKFFuncRun func  = new SKFFuncRun(this);
        if(null == baseAdapter){
            baseAdapter = new BaseAdapter() {
                @Override
                public int getCount() {
                    return 8;
                }

                @Override
                public Object getItem(int position) {
                    return null;
                }

                @Override
                public long getItemId(int position) {
                    return 0;
                }

                @Override
                public View getView(int position, View convertView, ViewGroup parent) {
                    if(null == convertView){
                        convertView = LayoutInflater.from(SkfListActivity.this).inflate(R.layout.layout_skf,null);
                    }

                    TextView textView = convertView.findViewById(R.id.spinner_desc);
                    Spinner spinner = convertView.findViewById(R.id.spinner);

                    textView.setText(SkfFunc.handleDesc.get(position));
                    switch (position){
                        case 0:
                            spinner.setAdapter(new ArrayAdapter<>(SkfListActivity.this,android.R.layout.simple_list_item_1,SkfFunc.devNames.toArray()));
                            spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                                @Override
                                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                    devNamePosition = position;
                                }

                                @Override
                                public void onNothingSelected(AdapterView<?> parent) {

                                }
                            });
                            break;
                        case 1:
                            spinner.setAdapter(new ArrayAdapter<>(SkfListActivity.this,android.R.layout.simple_list_item_1,SkfFunc.appNames.toArray()));
                            spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                                @Override
                                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                    appNamePosition = position;
                                }

                                @Override
                                public void onNothingSelected(AdapterView<?> parent) {

                                }
                            });
                            break;

                        case 2:
                            spinner.setAdapter(new ArrayAdapter<>(SkfListActivity.this,android.R.layout.simple_list_item_1,SkfFunc.containerNames.toArray()));
                            spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                                @Override
                                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                    containerNamePosition = position;
                                }

                                @Override
                                public void onNothingSelected(AdapterView<?> parent) {

                                }
                            });
                            break;

                        case 3:
                            spinner.setAdapter(new ArrayAdapter<>(SkfListActivity.this,android.R.layout.simple_list_item_1,SkfFunc.fileNames.toArray()));
                            spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                                @Override
                                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                    filePosition = position;
                                }

                                @Override
                                public void onNothingSelected(AdapterView<?> parent) {

                                }
                            });
                            break;

                        case 4:
                            spinner.setAdapter(new ArrayAdapter<>(SkfListActivity.this,android.R.layout.simple_list_item_1,SkfFunc.devhandles.toArray()));
                            spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                                @Override
                                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                    devPosition = position;
                                }

                                @Override
                                public void onNothingSelected(AdapterView<?> parent) {

                                }
                            });
                            break;
                        case 5:
                            spinner.setAdapter(new ArrayAdapter<>(SkfListActivity.this,android.R.layout.simple_list_item_1,SkfFunc.happlications.toArray()));
                            spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                                @Override
                                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                    appPosition = position;
                                }

                                @Override
                                public void onNothingSelected(AdapterView<?> parent) {

                                }
                            });
                            break;
                        case 6:
                            spinner.setAdapter(new ArrayAdapter<>(SkfListActivity.this,android.R.layout.simple_list_item_1,SkfFunc.hcontainers.toArray()));
                            spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                                @Override
                                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                    containerPosition = position;
                                }

                                @Override
                                public void onNothingSelected(AdapterView<?> parent) {

                                }
                            });
                            break;
                        case 7:
                            spinner.setAdapter(new ArrayAdapter<>(SkfListActivity.this,android.R.layout.simple_list_item_1,SkfFunc.handles.toArray()));
                            spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                                @Override
                                public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                                    handlePosition = position;
                                }

                                @Override
                                public void onNothingSelected(AdapterView<?> parent) {

                                }
                            });
                            break;
                    }


                    return convertView;
                }
            };
        }



        spinner.setAdapter(new ArrayAdapter<>(SkfListActivity.this,android.R.layout.simple_list_item_1,SkfFunc.list));
        spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                funcName = SkfFunc.list.get(position);
                funcPosition = position;
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {

            }
        });



        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                textViewCall.setText("当前调用的函数为"+funcName);
                long ret = SKFFuncRun.skf_run(funcPosition,devNamePosition,appNamePosition,containerNamePosition,filePosition,devPosition,appPosition,containerPosition,handlePosition,textViewResult);
                listView.setAdapter(baseAdapter);
            }
        });

    }

}
