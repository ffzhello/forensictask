package cn.edu.jslab6.autoresponse.forensictask;

import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * @description: 分析日志信息
 * @author: ffzheng
 * @create: 2019-01-12 14:09:40
 **/
public class LogAnalysisManager {
    private static Logger LOG = LoggerFactory.getLogger(LogAnalysisManager.class);
    private static Properties properties = new Properties();

    private ActiveTask activeTask = null;
    private Map<String,String> serviceMap = new HashMap<>();

    static {
        try {
            properties.load(new FileInputStream("./mongofield.properties"));
        } catch (IOException e) {
            LOG.debug("load mongofield.properties fail...");
        }
    }

    //
    public LogAnalysisManager(ActiveTask activeTask) {
        this.activeTask = activeTask;
    }

    /**
     * 日志分析
     */
    public void logAnalysis() {
        // 数据预处理
        if (activeTask == null || (preparedHandle(activeTask) != 0))
            return;

        String path = activeTask.getDirPath() + activeTask.cycle + "/";
        ArrayList<String> txt = FileManager.getFiles(path, "txt");
        if (txt.isEmpty())
            return;

        for (String file: txt) {
            //去掉文件扩展名
            int index = file.indexOf(".");
            String filename = file.substring(0,index);
            String log = filename + ".log";

            if (file.startsWith("conn"))
                continue;

            ArrayList<Document> documents = null;
            //协议日志
            if (BroLogType.protocolLogSet.contains(log)) {
                 documents = protocoltxt2Documents(filename);
            } else if (BroLogType.fileLogSet.contains(log)){
                 documents = filetxt2Documents(filename);
            } else {
                 documents = weirdtxt2Documents(filename);
            }

            // 入库
            if (documents != null && !(documents.isEmpty())) {
                documents2Db(filename+"log",documents);
            }
        }
        //conn.log后处理，用来富化service字段
        if (txt.contains("conn.txt")) {
            ArrayList<Document> documents = conntxt2Documents("conn");
            //入库
            if (documents != null && !(documents.isEmpty())) {
                documents2Db("connlog",documents);
            }
        }
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

    /**
     * 日志预处理，提取字段到txt
     * @param task
     * @return
     */
    private int preparedHandle(ActiveTask task) {
        //bro-cut
        String path = task.getDirPath() + task.cycle + "/" + "bro_detect/";
        ArrayList<String> files = FileManager.getFiles(path, "log");

        // weird.log和Suricata警报单独处理
        if (files.contains("weird.log")) {
            // 处理两类警报信息
            try {
                String simpleAlert = task.getDirPath() + task.cycle + "/weird.txt";
                genSimpleAlert(task.getDirPath()+task.cycle, simpleAlert);
            } catch (IOException e) {
                e.printStackTrace();
            } catch (InterruptedException e) {
                e.printStackTrace();
            } finally {
                //
            }
        }

        // 处理bro其他日志
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
                if ("weird.log".equals(file))
                    continue;

                int index = file.indexOf(".");
                String filename = file.substring(0,index);

                if (BroLogType.connLogSet.contains(file) || BroLogType.protocolLogSet.contains(file) || BroLogType.fileLogSet.contains(file) || BroLogType.weirdLogSet.contains(file))  {
                    String args = properties.getProperty(filename);
                    String cmd = "cat " + file + " | bro-cut -F '`' " + args + " > ../" + filename + ".txt";
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

            String[] cmds = {"/bin/sh", "-c", commands};
            File dir = new File(path);
            BufferedReader bufferedReader = null;
            try {
                Process process = Runtime.getRuntime().exec(cmds, null, dir);
                //等待执行完成
                process.waitFor();

                InputStream in = process.getInputStream();
                bufferedReader = new BufferedReader(new InputStreamReader(in));
                while ((bufferedReader.readLine()) != null) {
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

    /**
     * 连接日志txt转documents
     * @return
     */
    private ArrayList<Document> conntxt2Documents(String file) {
        ArrayList<Document> documents = new ArrayList<>();

        int taskId = activeTask.getId();
        String cycle = activeTask.cycle;

        String property = properties.getProperty(file);
        String[] fieldName = property.split("\\s+");

        //读取数据
        String filepath = activeTask.getDirPath() + activeTask.cycle + "/" + file + ".txt";
        File f = new File(filepath);
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(f));
            String tempString;
            // 一次读入一行，直到读入null为文件结束
            while ((tempString = reader.readLine()) != null) {

                // 处理每条记录
                String[] fieldValue = tempString.split("`");
                if (fieldName.length != fieldValue.length)
                    continue;

                // 计算开始时间
                fieldValue[1] = TimeManager.changeTsToString(fieldValue[1]);

                // 服务富化
                if ("-".equals(fieldValue[7]) && serviceMap.containsKey(fieldValue[0])) {
                    fieldValue[7] = serviceMap.get(fieldValue[0]);
                } else if (fieldValue[7].contains(",")) {
                    String[] services = fieldValue[7].split(",");
                    String ss = "";
                    for (String service: services) {
                        if (BroLogType.protocolLogSet.contains(service+".log")) {
                            ss += service + ",";
                        }
                    }
                    fieldValue[7] = ss;
                } else if (!("-".equals(fieldValue[7])) && !(BroLogType.protocolLogSet.contains(fieldValue[7]+".log"))){ //过滤未知服务icmp等
                    continue;
                }

                Document document = new Document();
                for (int pos = 0; pos < fieldName.length; pos++) {
                    document.put(fieldName[pos], fieldValue[pos]);
                }

                // ip用long形式冗余，便于聚合索引，提高页面加载速度
                String taskIp = fieldValue[4];
                String peerIp = fieldValue[2];

                String ipStr = activeTask.getIpString();
                if (ipStr.contains(fieldValue[2])) {
                    taskIp = fieldValue[2];
                    peerIp = fieldValue[4];
                }

                long taskIpLong = (taskIp.equals("-")? 0: IpUtils.ipToLong(taskIp));
                long peerIpLong = (peerIp.equals("-")? 0: IpUtils.ipToLong(peerIp));

                document.put("taskid", taskId);
                document.put("taskip", taskIpLong);
                document.put("peerip", peerIpLong);
                document.put("cycle", cycle);

                // 连接日志冗余追踪ip流量大小、对端ip流量大小信息，提高页面加载速度
                long taskPkts = ("-".equals(fieldValue[10]))? 0: Long.valueOf(fieldValue[10]);
                long taskBytes = ("-".equals(fieldValue[11]))? 0: Long.valueOf(fieldValue[11]);
                long peerPkts = ("-".equals(fieldValue[8]))? 0: Long.valueOf(fieldValue[8]);
                long peerBytes = ("-".equals(fieldValue[9]))? 0: Long.valueOf(fieldValue[9]);

                if (taskIp.equals(fieldValue[2])) {
                    taskPkts = ("-".equals(fieldValue[8]))? 0: Long.valueOf(fieldValue[8]);
                    taskBytes = ("-".equals(fieldValue[9]))? 0: Long.valueOf(fieldValue[9]);
                    peerPkts = ("-".equals(fieldValue[10]))? 0: Long.valueOf(fieldValue[10]);
                    peerBytes = ("-".equals(fieldValue[11]))? 0: Long.valueOf(fieldValue[11]);
                }
                document.put("task_pkts", taskPkts);
                document.put("task_bytes", taskBytes);
                document.put("peer_pkts", peerPkts);
                document.put("peer_bytes", peerBytes);

                documents.add(document);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    return documents;
                }
            }
            return documents;
        }
    }

    /**
     * 协议日志txt转documents
     * @return
     */
    private ArrayList<Document> protocoltxt2Documents(String file) {
        ArrayList<Document> documents = new ArrayList<>();

        int taskId = activeTask.getId();
        String cycle = activeTask.cycle;

        String property = properties.getProperty(file);
        String[] fieldName = property.split("\\s+");
        int length =  fieldName.length;

        //读取数据
        String filepath = activeTask.getDirPath() + activeTask.cycle + "/" + file + ".txt";
        File f = new File(filepath);
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(f));
            String tempString;
            // 一次读入一行，直到读入null为文件结束
            while ((tempString = reader.readLine()) != null) {

                // 处理每条记录
                String[] fieldValue = tempString.split("`");
                if (length != fieldValue.length)
                    continue;

                // 计算开始时间
                fieldValue[1] = TimeManager.changeTsToString(fieldValue[1]);

                Document document = new Document();
                for (int pos = 0; pos < fieldName.length; pos++) {
                    document.put(fieldName[pos], fieldValue[pos]);
                }

                // ip用long形式冗余，便于聚合索引，提高页面加载速度
                String taskIp = fieldValue[4];
                String peerIp = fieldValue[2];

                String ipStr = activeTask.getIpString();
                if (ipStr.contains(fieldValue[2])) {
                    taskIp = fieldValue[2];
                    peerIp = fieldValue[4];
                }

                long taskIpLong = (taskIp.equals("-")? 0: IpUtils.ipToLong(taskIp));
                long peerIpLong = (peerIp.equals("-")? 0: IpUtils.ipToLong(peerIp));

                document.put("taskid", taskId);
                document.put("taskip", taskIpLong);
                document.put("peerip", peerIpLong);
                document.put("cycle", cycle);

                // 用于connlog富化service
                serviceMap.put(fieldValue[0],file);

                documents.add(document);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    return documents;
                }
            }
            return documents;
        }
    }

    /**
     * 文件日志txt转documents
     * @return
     */
    private ArrayList<Document> filetxt2Documents(String file) {
        ArrayList<Document> documents = new ArrayList<>();

        int taskId = activeTask.getId();
        String cycle = activeTask.cycle;

        String property = properties.getProperty(file);
        String[] fieldName = property.split("\\s+");

        //读取数据
        String filepath = activeTask.getDirPath() + activeTask.cycle + "/" + file + ".txt";
        File f = new File(filepath);
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(f));
            String tempString;
            // 一次读入一行，直到读入null为文件结束
            while ((tempString = reader.readLine()) != null) {

                // 处理每条记录
                String[] fieldValue = tempString.split("`");
                if (fieldName.length != fieldValue.length)
                    continue;

                // 计算开始时间
                fieldValue[1] = TimeManager.changeTsToString(fieldValue[1]);

                Document document = new Document();
                for (int pos = 0; pos < fieldName.length; pos++) {
                    document.put(fieldName[pos], fieldValue[pos]);
                }

                if ("files".equals(file)) {
                    // ip用long形式冗余，便于聚合索引，提高页面加载速度
                    String taskIp = fieldValue[4];
                    String peerIp = fieldValue[2];

                    String ipStr = activeTask.getIpString();
                    if (ipStr.contains(fieldValue[2])) {
                        taskIp = fieldValue[2];
                        peerIp = fieldValue[4];
                    }

                    long taskIpLong = (taskIp.equals("-")? 0: IpUtils.ipToLong(taskIp));
                    long peerIpLong = (peerIp.equals("-")? 0: IpUtils.ipToLong(peerIp));

                    document.put("taskid", taskId);
                    document.put("taskip", taskIpLong);
                    document.put("peerip", peerIpLong);
                    document.put("cycle", cycle);
                }

                documents.add(document);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    return documents;
                }
            }
            return documents;
        }
    }

    /**
     * 警报日志txt转documents
     * @return
     */
    private ArrayList<Document> weirdtxt2Documents(String file) {
        ArrayList<Document> documents = new ArrayList<>();

        int taskId = activeTask.getId();
        String cycle = activeTask.cycle;

        String property = properties.getProperty(file);
        String[] fieldName = property.split("\\s+");

        //读取数据
        String filepath = activeTask.getDirPath() + activeTask.cycle + "/" + file + ".txt";
        File f = new File(filepath);
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(f));
            String tempString;
            // 一次读入一行，直到读入null为文件结束
            while ((tempString = reader.readLine()) != null) {

                // 处理每条记录
                String[] fieldValue = tempString.split("`");
                if (fieldName.length != fieldValue.length)
                    continue;

                Document document = new Document();
                for (int pos = 0; pos < fieldName.length; pos++) {
                    document.put(fieldName[pos], fieldValue[pos]);
                }

                // ip用long形式冗余，便于聚合索引，提高页面加载速度
                String taskIp = fieldValue[4];
                String peerIp = fieldValue[2];

                String ipStr = activeTask.getIpString();
                if (ipStr.contains(fieldValue[2])) {
                    taskIp = fieldValue[2];
                    peerIp = fieldValue[4];
                }

                long taskIpLong = (taskIp.equals("-")? 0: IpUtils.ipToLong(taskIp));
                long peerIpLong = (peerIp.equals("-")? 0: IpUtils.ipToLong(peerIp));

                document.put("taskid", taskId);
                document.put("taskip", taskIpLong);
                document.put("peerip", peerIpLong);
                document.put("cycle", cycle);

                documents.add(document);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    return documents;
                }
            }
            return documents;
        }
    }

    /**
     * 文档入库
     * @param documents
     */
    private void documents2Db(String collectionName, ArrayList<Document> documents) {
        MongoDatabase mongoDb = MongoDbManager.getMongoDB();
        MongoCollection<Document> collection = mongoDb.getCollection(collectionName);
        collection.insertMany(documents);
    }
}
