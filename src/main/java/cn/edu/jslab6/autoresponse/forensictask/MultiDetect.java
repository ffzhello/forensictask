package cn.edu.jslab6.autoresponse.forensictask;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class ActiveT {
    private String filename;
    private String dirPath;

    public void setFilename(String filename) {
        this.filename = filename;
    }
    public String getFilename() {
        return filename;
    }

    public void setDirPath(String dirPath) {
        this.dirPath = dirPath;
    }

    public String getDirPath() {
        return dirPath;
    }
}
/**
 * Created by ffzheng on 2018/6/23.
 */
public class MultiDetect implements Runnable {
    private ActiveT task = null;

    public MultiDetect(ActiveT task) {
        this.task = task;
    }

    private int doSuricataDetect(String pcapPath, String dir) throws InterruptedException, IOException {
        if (pcapPath == null || pcapPath.equals(""))  {
            System.out.println("No pcap file, Suricata Detect would return false.");
            return -1;
        }

        if (!pcapPath.endsWith(".pcap")) {
            System.out.println("{} is not a pcap file.");
            return -1;
        }

        File pcapFile = new File(pcapPath);
        String dirPath ;
        if (dir != null)
            dirPath = dir;
        else
            dirPath = pcapFile.getParent();
        File alertOutDir = new File(dirPath, "suricata_detect");

        alertOutDir.mkdir();

        String cmd = "suricata -r " + pcapPath + " -c /etc/suricata/suricata.yaml -l " + alertOutDir;

        Process process = Runtime.getRuntime().exec(cmd);

        process.waitFor();


        if (process.exitValue() != 0) {
            System.out.println("Suricata detect failed!");
            return -1;
        }

        System.out.println("Finish suricata detect.");
        return 0;
    }


    private int doBroDetect(String pcapPath, String dir) throws InterruptedException, IOException {
        //Thread.sleep(300);
        if (pcapPath == null || pcapPath.equals(""))  {
            System.out.println("No pcap file, Bro detect would return false.");
            return -1;
        }

        if (!pcapPath.endsWith(".pcap")) {
            System.out.println("{} is not a pcap file.");
            return -1;
        }

        File pcapFile = new File(pcapPath);
        String dirPath;
        if(dir != null)
            dirPath = dir;
        else
            dirPath = pcapFile.getParent();

        File alertOutDir = new File(dirPath, "bro_detect");
        alertOutDir.mkdir();

        String cmd = "bro -r " + pcapPath;

        Process process = Runtime.getRuntime().exec(cmd, null, alertOutDir);

        process.waitFor();


        if (process.exitValue() != 0) {
            System.out.println("Bro detect failed!");
            return -1;
        }

        System.out.println("Finish bro detect.");
        return 0;
    }

    @Override
    public void run() {
        String pcapFile = task.getFilename();
        String dir = task.getDirPath();

        try {
            doSuricataDetect(pcapFile,dir);
            doBroDetect(pcapFile,dir);
        }catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        int n = Integer.parseInt(args[0]);
        ExecutorService excetor = Executors.newCachedThreadPool();
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("YYYY-MM-DD hh:mm:ss");
        System.out.println(simpleDateFormat.format(new Date()));
        for (int i = 1; i <= n; i++) {
            ActiveT task = new ActiveT();
            task.setFilename("/home/monster/AutoResponse/HydraSensor/data/test/8.pcap");
            task.setDirPath("/home/monster/AutoResponse/HydraSensor/data/test/" + Integer.toString(i) + "/");

            excetor.execute(new MultiDetect(task));
        }
        excetor.shutdown();
        while(true) {
            if (excetor.isTerminated()) {
                System.out.println("all threads over..");
                break;
            }
        }
        System.out.println(simpleDateFormat.format(new Date()));
    }
}
