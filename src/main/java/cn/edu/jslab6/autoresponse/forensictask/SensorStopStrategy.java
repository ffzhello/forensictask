package cn.edu.jslab6.autoresponse.forensictask;

public class SensorStopStrategy {
    /**
     * 采集任务停止策略
     * 目前以流量采集大小超过100M为停止标准
     * @param task
     * @return
     */
    public static boolean canStop(ActiveTask task) {
        //大于100M,或采集时间超过10天
        return (task.getSensorBytes()>25*1024*1024)? true:false;
    }
}
