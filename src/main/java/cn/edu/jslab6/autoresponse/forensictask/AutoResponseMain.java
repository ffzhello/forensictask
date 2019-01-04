package cn.edu.jslab6.autoresponse.forensictask;

/**
 * Created by zrwang on 2016/12/12.
 * TODO: 1. 程序退出时，进行相关清除工作(e.g. 交换机上ACL规则的清除，数据库相关标志位的清除)
 *       2. 残留任务的处理(考虑持久化存储在硬盘文件中？), 每次启动时载入，或采集某种策略进行抛弃？
 *       3. 功能基本完善后，配置文件的抽取。
 */

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The main Process.
 */
public class AutoResponseMain {
    private static final Logger LOG = LoggerFactory.getLogger(AutoResponseMain.class);
    private static final String CONF_FILE = "./system.properties";
    private static final int NCPU = Runtime.getRuntime().availableProcessors();

    public static void main(String[] args) throws InterruptedException, IOException {
        //读取配置文件
        SystemConfig systemConfig = new SystemConfig(CONF_FILE);

        /*
         用来从CHAIRS接收案件信息, 并将响应任务存入TaskManager中.
          */
        ResponseTaskHttpServer httpServer = new ResponseTaskHttpServer(systemConfig);
        httpServer.start(); 
        LOG.info("启动任务接收HTTP服务器成功..");

        /*
        启动任务管理线程
        将Chairs发送过来的任务生成活动任务，存入数据库
         */
        TaskManager taskManager = new TaskManager();
        Thread taskManagerThread = new Thread(taskManager);
        taskManagerThread.start();
        LOG.info("Start task manager...");
        /**
        启动pcap文件离线切分线程
        离线分离pcap文件，匹配相应任务
         */
        PcapFileOfflineSplit offlineSplit = new PcapFileOfflineSplit();
        Thread splitThread = new Thread(offlineSplit);
        splitThread.start();
        LOG.info("启动离线分割线程成功..");

    }
}
