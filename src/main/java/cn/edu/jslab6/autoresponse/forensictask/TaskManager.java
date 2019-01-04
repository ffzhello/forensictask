package cn.edu.jslab6.autoresponse.forensictask;

import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.List;

/**
 * Created by ffzheng on 2017/7/19.
 */
public class TaskManager implements Runnable{
    private static final Logger LOG = LoggerFactory.getLogger(TaskManager.class);

    String sql = null;
    private static final int NUM = 3200;
    private static ArrayBlockingQueue<ResponseTask> unHandledTaskQueue = new ArrayBlockingQueue<ResponseTask>(NUM);

    //保存Chairs发送的任务
    public static void addUnhandledTask(ResponseTask task) throws InterruptedException {
        if(task == null) {
            return;
        }
        unHandledTaskQueue.put(task);
        LOG.debug("Task[ticketid:" + task.getTicketid() + "] receive success");
    }

    //取出任务
    private static ResponseTask getUnhandledTask() throws InterruptedException {
        ResponseTask task = unHandledTaskQueue.take();
        return task;
    }

    //将任务存入数据库
    @Override
    public void run() {
        while(true) {
            //有没有强制停止任务

            ResponseTask task = null;
            try {
                task = getUnhandledTask();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            if (task != null) {

                //根据action过滤
                List<ResponseAction> actionList = task.getActions();
                if(actionList.contains(ResponseAction.PcapCap)) {
                    //将活动任务插入数据库activetask活动任务表中
                    long starttime = (System.currentTimeMillis())/1000;
                    long endtime = starttime + task.getTimelen();

                    //去除重复案件
                    sql = "SELECT COUNT(*) FROM activetask WHERE ticketid = " + task.getTicketid() + " AND status < " + TaskStatus.FINISHED.getValue() +";";
                    Connection conn = null;
                    Statement statement = null;
                    ResultSet resultSet = null;
                    try {
                        conn = DruidDataSourcePool.getConnection();

                        statement = conn.createStatement();
                        resultSet = statement.executeQuery(sql);

                        int count = 0;
                        while (resultSet.next()) {
                            count = resultSet.getInt(1);
                        }
                        if (count == 0) {
                            sql = "INSERT INTO activetask(ticketid, caseid, iplist, action, priority, inoutflag," +
                                    "srcipflag, srcipdstip, dstipflag, srcport, srcportdstport, dstport, protocol," +
                                    "starttime, endtime, sensorbytes, thresholdpkts, filesplit, username, status) VALUES(" +
                                    task.getTicketid() + ",\"" + task.getCaseid() + "\",\""  + task.ipListToString() + "\",\"" + task.getRawActions() + "\"," +
                                    task.getPriority() + "," + task.getFlowDirection() + "," + task.getSrcIP() + "," +
                                    task.getSrcIPDstIP() + "," + task.getDstIP() + "," + task.getSrcPort() + "," +
                                    task.getSrcPortDstPort() + "," + task.getDstPort() + "," + task.getProtocol() + "," +
                                    starttime + "," + endtime + "," + 0 + "," + task.getThresholdPkts() + "," + task.getFilesplit() +
                                    ",\"" + task.getUsername() + "\"," + TaskStatus.WAIT_SENSOR.getValue() + ");";

                            statement.executeUpdate(sql);

                        }else {
                            LOG.debug("数据库已存在该案件[ticketid: "+ task.getTicketid() +"]的采集任务");
                        }
                    }catch (SQLException e) {
                        LOG.debug("新采集任务[ticketid:" + task.getTicketid() + "]插入数据库失败...");
                        e.printStackTrace();
                    } finally {
                        if (resultSet != null) {
                            try {
                                resultSet.close();
                            } catch (SQLException e) {
                                e.printStackTrace();
                            }
                        }
                        if (statement!= null) {
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
                }else
                    LOG.debug("新任务不要采集报文..");
            }
        }
    }

    public static void main(String[] args) {

    }
}
