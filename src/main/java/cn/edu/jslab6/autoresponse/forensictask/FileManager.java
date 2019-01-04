package cn.edu.jslab6.autoresponse.forensictask;

import com.google.gson.Gson;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by ffzheng on 2017/9/18.
 */
public class FileManager {

    //判断文件是否存在
    public static boolean isFileExists(String filename) {
        boolean exists = false;
        if (filename != null && !filename.isEmpty()){
            File file = new File(filename);
            if(file.exists() && file.isFile())
                exists = true;
        }
        return exists;
    }

    //创建目录
    public static void createDir(ActiveTask task) {
        if (task == null)
            return;

        //任务采集、分析结果保存路径
        String parentDir = task.getDirPath();
        //创建目录
        File dir = new File(parentDir);
        if (dir.exists() && dir.isDirectory())
            deleteFile(dir);

        dir.mkdirs();
    }

    //创建目录
    public static void createDir(List<ActiveTask> taskList) {
        if (taskList == null || taskList.isEmpty())
            return;

        for(ActiveTask t: taskList) {
            //任务采集、分析结果保存路径
            String parentDir = t.getDirPath();
            //创建目录
            File dir = new File(parentDir);
            if (dir.exists() && dir.isDirectory())
                deleteFile(dir);

            dir.mkdirs();
        }
    }

    //创建任务周期目录
    public static void createDir(String path) {
        if (path == null || path == "")
            return;
        File dir = new File(path);
        if (dir.exists()) {
            if (!(dir.isDirectory())) {
                dir.mkdirs();
            }
        }else {
            dir.mkdirs();
        }
    }


    //删除目录或文件
    public static void deleteFile(File file) {
        if (file.exists()) {//判断文件是否存在
            if (file.isFile()) {//判断是否是文件
                file.delete();//删除文件
            } else if (file.isDirectory()) {//否则如果它是一个目录
                File[] files = file.listFiles();//声明目录下所有的文件 files[];
                for (int i = 0;i < files.length;i ++) {//遍历目录下所有的文件
                    deleteFile(files[i]);//把每个文件用这个方法进行迭代
                }
                file.delete();//删除文件夹
            }
        } else {
            //System.out.println("所删除的文件不存在");
        }
    }

    //获取某个目录底下所有文件
    public static ArrayList<String> getFiles(String path, String suffix) {
        ArrayList<String> filenames = new ArrayList<String>();
        File file = new File(path);
        if (file != null) {
            File[] files = file.listFiles();
            if (files != null && files.length > 0) {
                for (File f: files) {
                    String filename = f.getName();
                    if (filename.endsWith(suffix))
                        filenames.add(filename);
                }
            }
        }
        return filenames;
    }

    public static void readFileByLines(String fileName) {
        File file = new File(fileName);
        BufferedReader reader = null;
        try {
            System.out.println("以行为单位读取文件内容，一次读一整行：");
            reader = new BufferedReader(new FileReader(file));
            String tempString = null;
            int line = 1;
            // 一次读入一行，直到读入null为文件结束
            while ((tempString = reader.readLine()) != null) {
                // 显示行号
                line++;
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e1) {
                }
            }
        }
    }

    public static void main(String[] args) {
        File file = new File("E:/eve.json");
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(file));
            String tempString = null;
            int line = 0;
            // 一次读入一行，直到读入null为文件结束
            while ((tempString = reader.readLine()) != null) {
                if (tempString.contains("\"event_type\":\"alert\"")) {
                    String[] strArr = tempString.split(",");
                    //获取uid

                    //获取时间戳

                    //获取srcip

                    //获取srcport

                    //获取dstip

                    //获取dstport

                    //获取name
                }
            }
            System.out.println(line);
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e1) {
                }
            }
        }
    }
}
