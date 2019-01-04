package cn.edu.jslab6.autoresponse.forensictask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class PeerIpSensorInfoManager {
    private static final Logger LOG = LoggerFactory.getLogger(ActiveTask.class);

    //insert
    public static void insert(int taskid, String cycle, String taskip, String peerip, long sensorpkts, long sensorbytes, String detectresults) {
        //检测当前SQL数据库连接是否有效(Mysql8小时问题),如果连接已经被关闭，则重新初始化当前数据库连接。
        Connection conn = null;
        Statement statement = null;
        try {
            conn = DruidDataSourcePool.getConnection();

            statement = conn.createStatement();
            String sql = "INSERT INTO peeripsensorinfo(taskid, cycle, taskip, peerip, sensorpkts, sensorbytes, detectresults)VALUES(" + taskid + ",\"" + cycle + "\",\"" + taskip + "\",\"" + peerip + "\"," + sensorpkts + "," + sensorbytes + ",\"" + detectresults + "\")";

            statement.executeUpdate(sql);
        }catch (SQLException e) {
            LOG.debug("对端信息插入失败...");
            e.printStackTrace();
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
}
