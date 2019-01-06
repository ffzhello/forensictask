package cn.edu.jslab6.autoresponse.forensictask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.CountDownLatch;

/**
 * Created by ffzheng on 2018/6/25.
 */
public class ConcurrentDetection implements Runnable {

    private static Logger LOG = LoggerFactory.getLogger(ConcurrentDetection.class);
    private ActiveTask activeTask = null;
    private CountDownLatch countDownLatch = null;
    private Map<String,String> serviceMap = new HashMap<>();

    public ConcurrentDetection(ActiveTask activeTask, CountDownLatch countDownLatch) {
        this.countDownLatch = countDownLatch;
        this.activeTask = activeTask;
    }

    @Override
    public void run() {
        if (activeTask == null || countDownLatch == null)
            return;

        try {
            String dir = activeTask.getDirPath();
            String cycle = activeTask.cycle;

            //待检测文件位置
            String filename = dir + cycle + "/" + "cycle.pcap";

            //离线检测
            List<ResponseAction> actions = activeTask.getActionList();

            activeTask.responseResult = new ResponseResult();
            activeTask.responseResult.ticketid = String.valueOf(activeTask.getTicketId());
            activeTask.responseResult.actionResult.put(ResponseAction.SuricataDetect, false);
            activeTask.responseResult.actionResult.put(ResponseAction.BroDetect, false);


            if (actions.contains(ResponseAction.SuricataDetect)) {
                if (doSuricataDetect(filename) == 0)
                    activeTask.responseResult.actionResult.put(ResponseAction.SuricataDetect, true);
            }

            if (actions.contains(ResponseAction.BroDetect)) {
                if (doBroDetect(filename) == 0)
                    activeTask.responseResult.actionResult.put(ResponseAction.BroDetect, true);
            }

            /*// Suricata检测和Bro检测至少有一个成功后，进行IDS融合警报的生成。
            if (activeTask.responseResult.actionResult.get(ResponseAction.SuricataDetect) ||
                    activeTask.responseResult.actionResult.get(ResponseAction.BroDetect)) {
                File simpleAlert = new File("SimpleAlert" + activeTask.getId() + ".txt");

                String outPath = simpleAlert.toString();

                activeTask.responseResult.files.fileName = outPath;
                if (genSimpleAlert(filename,outPath) == 0) {
                    //activeTask.responseResult.files.fileContent = Utils.readFileContent(outPath);
                }
            } else {
                activeTask.responseResult.files.fileName = "";
                activeTask.responseResult.files.fileContent = "";
            }*/
            // Suricata检测和Bro检测至少有一个成功后，进行IDS融合警报的生成。
            if (activeTask.responseResult.actionResult.get(ResponseAction.SuricataDetect) ||
                    activeTask.responseResult.actionResult.get(ResponseAction.BroDetect)) {
                // 处理两类警报信息

                // 处理日志信息
                logAnalysis(activeTask);
            }

            LOG.debug("[taskid:" + activeTask.getId() +"]检测完成");
        } catch (IOException e) {
            LOG.error("exception: [taskid:" + activeTask.getId() +"]检测失败......");
        } catch (InterruptedException e) {
            LOG.error("exception: [taskid:" + activeTask.getId() +"]检测失败......");
        } finally {
            countDownLatch.countDown();
        }
    }

    /**
     * Offline Suricata detect mode.
     * Suricata的离线检测结果将保存在filepath内的suricata_detect子目录中
     * @param pcapPath: 离线报文保存的绝对路径
     * @throws InterruptedException
     * @return 返回0代表Suricata检测成功，否则检测失败。
     */
    private int doSuricataDetect(String pcapPath) throws InterruptedException, IOException {
        if (pcapPath == null || pcapPath.equals(""))  {
            LOG.debug("No pcap file, Suricata Detect would return false.");
            return -1;
        }

        if (!pcapPath.endsWith(".pcap")) {
            LOG.debug("{} is not a pcap file.", pcapPath);
            return -1;
        }

        File pcapFile = new File(pcapPath);
        String parent = pcapFile.getParent();

        File alertOutDir = new File(parent, "suricata_detect");
        alertOutDir.mkdir();
        // TODO: 调用系统命令来执行suricata检测命令.
        // 命令如: suricata -r pcapPath -c /etc/suricata/suricata.yaml -l alertOutDir
        String cmd = "suricata -r " + pcapPath + " -c /etc/suricata/suricata.yaml -l " + alertOutDir;
        //LOG.debug(cmd);
        Process process = Runtime.getRuntime().exec(cmd);
        // 等待suricata检测结束
        process.waitFor();

        // FIXME: 可将子程序中的标准错误输出到错误日志中。
        if (process.exitValue() != 0) {
            LOG.debug("Suricata detect failed!");
            return -1;
        }
        return 0;
    }

    /**
     * Offline Bro detect mode.
     *   Bro的离线检测结果将保存在filePath内的bro_detect子目录中。
     * @param pcapPath: 离线报文保存的绝对路径
     * @return 返回0代表Bro检测成功，否则检测失败。
     * @throws InterruptedException
     * @throws IOException
     */
    private int doBroDetect(String pcapPath) throws InterruptedException, IOException {
        //Thread.sleep(300);
        if (pcapPath == null || pcapPath.equals(""))  {
            LOG.debug("No pcap file, Bro detect would return false.");
            return -1;
        }

        if (!pcapPath.endsWith(".pcap")) {
            LOG.debug("{} is not a pcap file.", pcapPath);
            return -1;
        }

        File pcapFile = new File(pcapPath);

        String parent = pcapFile.getParent();
        File alertOutDir = new File(parent, "bro_detect");
        alertOutDir.mkdir();

        String cmd = "bro -r " + pcapPath;
        // bro离线检测时，会在当前目录下生成相关检测结果，所以运行程序时，需要设置其working directory值。
        Process process = Runtime.getRuntime().exec(cmd, null, alertOutDir);
        // 等待Bro检测结果
        process.waitFor();

        // FIXME: 可将子程序中的标准错误输出到错误日志中。
        if (process.exitValue() != 0) {
            int index = parent.lastIndexOf("/");
            String name = parent.substring(index);
            LOG.error("Bro detect failed!");
            return -1;
        }
        return 0;
    }

    /**
     * 提取bro日志字段
     * @param task
     */
    private int preparedHandle(ActiveTask task) {
        //bro-cut
        String path = task.getDirPath() + task.cycle + "/" + "bro_detect/";
        ArrayList<String> files = FileManager.getFiles(path, "log");
        if (!files.isEmpty()) {
            Properties properties = new Properties();
            try {
                properties.load(new FileInputStream("./logextractrules.properties"));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
                return -1;
            } catch (IOException e) {
                e.printStackTrace();
                return -1;
            }

            //构造shell脚本
            ArrayList<String> cmdArr = new ArrayList<>();
            for (String file: files) {
                int index = file.indexOf(".");
                String filename = file.substring(0,index);

                if (BroLogType.connLogSet.contains(file) || BroLogType.protocolLogSet.contains(file) || BroLogType.fileLogSet.contains(file) || BroLogType.weirdLogSet.contains(file))  {
                    String args = properties.getProperty(filename);
                    String cmd = "cat " + file + " | bro-cut -F '`' " + args + " > ./" + filename + ".txt";
                    cmdArr.add(cmd);
                }
            }

            //没有待分析日志
            if (cmdArr.isEmpty())
                return -1;

            //调用本地shell
            String commands = "";
            for (int i = 0; i < cmdArr.size(); i++) {
                if (i != 0)
                    commands +=  "&& ";
                commands += cmdArr.get(i) + " ";
            }

            //LOG.debug(commands);

            String[] cmds = {"/bin/sh", "-c", commands};
            File dir = new File(path);
            BufferedReader bufferedReader = null;
            try {
                Process process = Runtime.getRuntime().exec(cmds, null, dir);
                //等待执行完成
                process.waitFor();

                InputStream in = process.getInputStream();
                bufferedReader = new BufferedReader(new InputStreamReader(in));
                String line = null;
                while ((line = bufferedReader.readLine()) != null) {
                    //non handle
                }
            } catch (IOException e) {
                e.printStackTrace();
                return -1;
            } catch (InterruptedException e) {
                e.printStackTrace();
                return -1;
            } finally {
                try {
                    if (bufferedReader != null) {
                        bufferedReader.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            return 0;
        }else {
            return -1;
        }
    }

    private String getSqlStr(String tablename, String[] fields) {
        int len = fields.length;

        String sqlStr = "\'";

        //构造sql语句
        for (int i = 0; i < len-1; i ++) {
            // 将字符串中的所有'字符转义，防止入库失败
            String replaceStr = fields[i].replaceAll("'","\\\\\'");
            sqlStr += replaceStr;
            sqlStr += "\',\'";
        }
        //最后一个字段
        sqlStr += fields[len-1] + "\'";

        return sqlStr;
    }

    /**
     * 日志入库
     */
    private void logToDb(ActiveTask task, String tablename, String[] fields) {
        if (task == null || tablename == null || fields == null || fields.length < 1)
            return;

        //入库
        String sql = "INSERT INTO " + tablename + "log VALUES(null,";
        sql += getSqlStr(tablename,fields);

        if ((!("software".equals(tablename))) && (!("pe".equals(tablename))) && (!("x509".equals(tablename)))) {
            //
            String taskIp = fields[4];
            String peerIp = fields[2];

            String ipStr = task.getIpString();
            if (ipStr.contains(fields[2])) {
                taskIp = fields[2];
                peerIp = fields[4];
            }
            // ip用long形式冗余，便于聚合索引，提高页面加载速度
            long taskIpLong = (taskIp.equals("-")? 0: IpUtils.ipToLong(taskIp));
            long peerIpLong = (peerIp.equals("-")? 0: IpUtils.ipToLong(peerIp));

            sql += "," + task.getId() + "," + taskIpLong + "," + peerIpLong + ",\'" + task.cycle + "\'";

            // 连接日志冗余追踪ip流量大小、对端ip流量大小信息，提高页面加载速度
            if ("conn".equals(tablename)) {
                String taskPkts = fields[10];
                String taskBytes = fields[11];
                String peerPkts = fields[8];
                String peerBytes = fields[9];

                if (taskIp.equals(fields[2])) {
                    taskPkts = fields[8];
                    taskBytes = fields[9];
                    peerPkts = fields[10];
                    peerBytes = fields[11];
                }
                sql += ",\'" + taskPkts + "\',\'" + taskBytes + "\',\'" + peerPkts + "\',\'" + peerBytes + "\'";
            }
        }
        sql += ")";

        Connection conn = null;
        Statement statement = null;
        try {
            conn = DruidDataSourcePool.getConnection();
            statement = conn.createStatement();

            statement.executeUpdate(sql);
        } catch (SQLException e) {
            LOG.error("exception: "+sql);
        } finally {
            if (statement != null) {
                try {
                    statement.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * log读取
     * @param file
     */
    private void logReader(ActiveTask task, String file) {
        //去掉文件扩展名
        int index = file.indexOf(".");
        String filename = file.substring(0,index);

        boolean protocolLog = false;
        boolean connLog = false;

        //如果是协议类型，获取服务map
        if (BroLogType.protocolLogSet.contains(filename+".log")) {
            protocolLog = true;
        }

        //如果是连接类型日志，富化服务字段
        if (BroLogType.connLogSet.contains(filename+".log")) {
            connLog = true;
        }

        //读取数据
        String filepath = task.getDirPath() + task.cycle + "/" + "bro_detect/" + file;
        File f = new File(filepath);
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(f));
            String tempString = null;
            // 一次读入一行，直到读入null为文件结束
            while ((tempString = reader.readLine()) != null) {
                // 处理每条记录
                String[] fields = tempString.split("`");
                if (fields.length < 2)
                    continue;
                if (protocolLog == true)
                    serviceMap.put(fields[0],filename);

                //时间戳处理
                fields[1] = TimeManager.changeTsToString(fields[1]);

                //conn.log富化service
                if (connLog == true && "-".equals(fields[7])) {
                    if (serviceMap.containsKey(fields[0]))
                        fields[7] = serviceMap.get(fields[0]);
                }
                //入库
                logToDb(task,filename,fields);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    serviceMap.clear();
                    reader.close();
                } catch (IOException e1) {
                }
            }
        }
    }

    /**
     * 日志分析
     * @param task
     */
    private void logAnalysis(ActiveTask task) {
        // 数据预处理
        if (task == null || (preparedHandle(task) != 0))
            return;

        String path = task.getDirPath() + task.cycle + "/bro_detect/";
        ArrayList<String> txt = FileManager.getFiles(path, "txt");
        if (txt.isEmpty())
            return;

        for (String file: txt) {
            //conn.log后处理，用来富化service字段
            if (file.startsWith("conn"))
                continue;
            logReader(task, file);
        }
        //conn.log
        if (txt.contains("conn.txt"))
            logReader(task, "conn.txt");

        //suricata.log
    }

    /**
     * 综合Suricata检测和Bro检测得到的日志文件生成警报日志文件
     * FIXME: 现阶段调用python脚本完成警报的转换。脚本主要完成：
     *        1. Suricata eve.json to simple alert.
     *        2. Bro weired.log to simple alert.
     *        3. simple alert将被放在{@param parentDir}内的simple_alert.txt中。
     * @param parentDir:
     * @return 返回0,代表生成IDS融合警报成功(警报将被放 {@param outAlertFile}中).否则生成融合警报失败。
     * @throws InterruptedException
     */
    private int genSimpleAlert(String parentDir, String outAlertFile) throws InterruptedException, IOException {
        //String ALERT_CONVERTER_PATH = "E:\\AlertConverter\\AlertConverter.py";
        // 调用脚本完成IDS融合警报生成, 脚本需要添加到java -cp选项内
        String cmd = "python AlertConverter.py -i " + parentDir + " -o " + outAlertFile;

        Process process = Runtime.getRuntime().exec(cmd);

        //等待融合警报的生成
        //程序执行到这里，跑不动了
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        while ((reader.readLine()) != null) {
            //
        }

        process.waitFor();

        if (process.exitValue() != 0) {
            LOG.debug("Generate Simple Alert failed!");
            return -1;
        }
        return 0;
    }

    public static void main(String[] args) throws ParseException {
        String sss = "hel'''lo" ;
        String fff = sss.replaceAll("'", "\\\\\'");
        System.out.println(fff);
    }
}
