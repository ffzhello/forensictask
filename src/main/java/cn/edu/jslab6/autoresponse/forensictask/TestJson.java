package cn.edu.jslab6.autoresponse.forensictask;

import com.google.gson.Gson;

import java.io.IOException;
import java.util.*;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Created by ffzheng on 2017/9/16.
 */
public class TestJson {
    public static void print() {
        for (int i=0; i < 10000; i ++) {
            System.out.println(i);
        }
    }

    public static void main(String[] args) throws IOException{
        ActiveTask task = new ActiveTask();
        task.setDirPath("E://");
        task.setPatFileCount(1);

        PcapFileManager.mergePcapfiles(task, true);

    }
}
