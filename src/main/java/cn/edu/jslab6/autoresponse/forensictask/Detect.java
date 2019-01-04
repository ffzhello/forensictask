package cn.edu.jslab6.autoresponse.forensictask;

import java.io.File;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Created by ffzheng on 2018/6/22.
 */
public class Detect {

    public static void main(String[] args) {
        if(args.length < 2)
            return;
        String pcapPath = args[1];
        String dir = "/home/monster/AutoResponse/HydraSensor/data/test/";
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("hh:mm:ss");
        System.out.println("Bro:");
        System.out.println(simpleDateFormat.format(new Date()));
        try {
            doBroDetect(pcapPath,dir);
        }catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(simpleDateFormat.format(new Date()));

        System.out.println("Suricata:");
        System.out.println(simpleDateFormat.format(new Date()));
        try {
            doSuricataDetect(pcapPath,dir);
        }catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(simpleDateFormat.format(new Date()));
    }

    private static int doBroDetect(String pcapPath, String dir) throws InterruptedException, IOException {
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

    private static int doSuricataDetect(String pcapPath, String dir) throws InterruptedException, IOException {
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
        System.out.println(cmd);
        Process process = Runtime.getRuntime().exec(cmd);

        process.waitFor();


        if (process.exitValue() != 0) {
            System.out.println("Suricata detect failed!");
            return -1;
        }

        System.out.println("Finish suricata detect.");
        return 0;
    }
}
