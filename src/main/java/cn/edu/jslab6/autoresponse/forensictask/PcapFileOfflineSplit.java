package cn.edu.jslab6.autoresponse.forensictask;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.pcap4j.core.*;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by ffzheng on 2017/7/19.
 */
public class PcapFileOfflineSplit implements Runnable{

    private static final Logger LOG = LoggerFactory.getLogger(PcapFileOfflineSplit.class);
    private PcapFileInfo pcapFileInfo = null;
    //任务总表
    private  Set<ActiveTask> sensorTasks = new HashSet<>();
    //任务ip映射表
    private Map<Long,Set> ruleToTasks = new HashMap<>();
    //当前周期有报文匹配的任务
    private Set<ActiveTask> cycleTasks = new HashSet<>();
    //限定每个任务的大小最大12M
    private static final int MAX_TASK_SIZE = 12582912;
    //限定每个文件的大小为5M
    private static final int MAX_TMPFILE_SIZE = 2097152;
    //定义任务响应线程池
    private ExecutorService executorService = Executors.newCachedThreadPool();

    public PcapFileOfflineSplit() {

        //系统重启时恢复之前正在采集的任务
        restoreSensoringTask();
    }

    /**
     * 恢复系统停掉前的采集任务
     */
    private void restoreSensoringTask() {
        List<ActiveTask> activeTasks = ActiveTaskManager.getTaskListfromDB(TaskStatus.SENSORING);

        if (!activeTasks.isEmpty()) {
            for (ActiveTask task: activeTasks) {
                //恢复现场
                File file = new File(task.getDirPath());
                if (file.exists()) {

                }else {
                    //创建目录
                    FileManager.createDir(task);
                }
                //建立规则任务映射关系
                buildRuleToTasks(task);
                sensorTasks.add(task);
                LOG.debug("从数据库恢复采集任务[taskid:" + task.getId() + "]成功.");
            }
        }
    }

    /**
     * 建立ip与任务的映射关系
     * @param task
     */
    private void buildRuleToTasks(ActiveTask task) {
        if (task == null)
            return;

        if (!task.getIpLongList().isEmpty()) {
            for (Long ip: task.getIpLongList()) {
                Set<ActiveTask> tasks;
                if (ruleToTasks.containsKey(ip))
                    tasks = ruleToTasks.get(ip);
                else
                    tasks = new HashSet<>();

                tasks.add(task);
                ruleToTasks.put(ip, tasks);
            }
        }
    }

    /**
     * 单个PCAP文件离线分离
     * @param pcapFile
     * @throws PcapNativeException
     * @throws NotOpenException
     * @throws IllegalRawDataException
     * @throws ArrayIndexOutOfBoundsException
     */
    private void splitPcapFile(PcapFileInfo pcapFile) {
        if (pcapFile == null)
            return;

        String pcapFileName = pcapFile.getFilepath();
        if (pcapFileName == null || pcapFileName.equals(""))
            return;

        //周期
        int start = pcapFileName.lastIndexOf("/");
        int end = pcapFileName.indexOf(".");
        String cycle = pcapFileName.substring(++start, end);

        LOG.debug(cycle + ".pcap分离开始.");

        Packet packet;
        PcapHandle handle = null;
        IpV4Packet ipV4Packet;
        IpV4Packet.IpV4Header header;
        Long srcIp;
        Long dstIp;

        try {
            System.out.println(pcapFileName);
            handle = Pcaps.openOffline(pcapFileName);
            while ((packet = handle.getNextPacket()) != null) {
                //数据包大小
                long packetSize = packet.length();

                ipV4Packet = packet.get(IpV4Packet.class);
                header = ipV4Packet.getHeader();

                String src = header.getSrcAddr().getHostAddress();
                String dst = header.getDstAddr().getHostAddress();
                srcIp = IpUtils.ipToLong(src);
                dstIp = IpUtils.ipToLong(dst);

                //匹配任务
                Set<ActiveTask> packetTaskSet = new HashSet<>();
                if (ruleToTasks.containsKey(srcIp)) {
                    packetTaskSet.addAll(ruleToTasks.get(srcIp));
                }
                if(ruleToTasks.containsKey(dstIp)) {
                    packetTaskSet.addAll(ruleToTasks.get(dstIp));
                }

                //周期内被匹配到的任务集合
                cycleTasks.addAll(packetTaskSet);

                //写入
                if (!packetTaskSet.isEmpty()) {
                    for (ActiveTask task: packetTaskSet) {
                        if (task.dumper == null) {
                            //当前周期的第一个报文
                            //创建周期目录
                            String path = task.getDirPath() + cycle;
                            FileManager.createDir(path);

                            task.dumper = handle.dumpOpen(path + "/cycle.pcap");
                            task.setFilename(path+"/");
                            task.cycle = cycle;
                        }
                        //写报文到周期文件
                        task.dumper.dump(packet, handle.getTimestamp());

                        //本周期已采集报文个数
                        task.cyclepkts++;
                        //本周期已采集报文大小
                        task.cyclebytes += packetSize;

                        //写报文到对端ip
                        String taskip = src;
                        String peerip = dst;
                        if (task.getIpString().contains(peerip)) {
                            taskip = dst;
                            peerip = src;
                        }
                        /*//根据对端ip分类
                        if (!(task.peerIpInfoMap.containsKey(peerip))) {
                            //创建对端ip目录
                            String path = task.getDirPath() + cycle + "/" + taskip + "-" + peerip;
                            FileManager.createDir(path);

                            PeerIpInfo peerIpInfo = new PeerIpInfo();
                            peerIpInfo.setTaskip(taskip);
                            peerIpInfo.setPeerip(peerip);
                            peerIpInfo.pcapDumper = handle.dumpOpen(path + "/" + peerip + ".pcap");

                            task.peerIpInfoMap.put(peerip, peerIpInfo);
                        }
                        //写报文到对端ip pcap文件中
                        PeerIpInfo peerIpInfo = task.peerIpInfoMap.get(peerip);
                        peerIpInfo.pcapDumper.dump(packet, handle.getTimestamp());
                        //报文大小及个数
                        long count = peerIpInfo.getSensorpkts();
                        peerIpInfo.setSensorpkts(++count);

                        long bytes = peerIpInfo.getSensorbytes();
                        peerIpInfo.setSensorbytes(bytes+packetSize);
                        //根据对端ip分类finish*/

                    }
                }
            }
        } catch (PcapNativeException e) {
            LOG.debug("Pcap Native Exception...");
        } catch (NotOpenException e) {
            LOG.debug("Not Open Exception...");
        } catch (ArrayIndexOutOfBoundsException e) {
            LOG.debug("Array Index Out Of Bounds Exception...");
        } finally {
            //关闭任务dumper
            if (!cycleTasks.isEmpty()) {
                for (ActiveTask t: cycleTasks) {
                    //关闭任务dumper
                    if (t.dumper != null && t.dumper.isOpen()) {
                        t.dumper.close();
                        t.dumper = null;
                    }
                    /*// 关闭对端ip的dumper
                    for(Map.Entry<String,PeerIpInfo> entry1: t.peerIpInfoMap.entrySet()) {
                        if (entry1.getValue().pcapDumper != null && entry1.getValue().pcapDumper.isOpen()) {
                            entry1.getValue().pcapDumper.close();
                            entry1.getValue().pcapDumper = null;
                        }
                    }*/
                }
            }
            if(handle != null) {
                //关闭handle
                handle.close();
            }
            LOG.debug(cycle + ".pcap分离结束.");
        }
    }

     /**
     * 任务强制停止后的处理
     * @param task
     */
    private void handlerForceTask(ActiveTask task) throws IOException{
        if (task == null)
            return;

        //合并merge文件
        PcapFileManager.mergePcapfiles(task, false);

        task.setStatus(TaskStatus.FINISHED.getValue());
        Long ts = System.currentTimeMillis() / 1000;
        ActiveTaskManager.updateActiveTaskStatusByTaskId(task.getId(), TaskStatus.FINISHED, ts);
        LOG.debug("任务[id:" + task.getId() + "]停止成功.");
    }

    /**
     * 从数据库读取任务、PCAP文件
     */
    @Override
    public void run() {

        while(true) {
            pcapFileInfo =  PcapFileManager.getUnhandlerPcapFile();

            //从数据库中读取等待执行的任务,并创建存储目录
            ActiveTaskManager activeTaskManager = new ActiveTaskManager();
            List<ActiveTask> taskList = activeTaskManager.getTaskListfromDB(TaskStatus.WAIT_SENSOR);
            FileManager.createDir(taskList);

            //build
            if (!taskList.isEmpty()) {
                for (ActiveTask task: taskList) {
                    buildRuleToTasks(task);
                }
            }

            //add to任务总表
            sensorTasks.addAll(taskList);

            if(pcapFileInfo != null) {
                LOG.debug("系统当前共有" + sensorTasks.size() + "个采集任务.");
                //以文件为单位心跳
                if (!(ruleToTasks.isEmpty())) {
                    //离线分离
                    splitPcapFile(pcapFileInfo);
                }

                //更新数据库中pcap文件信息，标记为已处理
                PcapFileManager.updatePcapFileInfoFromDB(pcapFileInfo.getId());

                //删除系统中的pcap文件
                String filePath = pcapFileInfo.getFilepath();
                File f = new File(filePath);
                if (f != null)
                    f.delete();


                int fCount = cycleTasks.size();
                if (fCount <= 0) {

                } else {
                    LOG.debug("周期内任务个数：" + fCount);
                    CountDownLatch countDownLatch = new CountDownLatch(fCount);

                    for (ActiveTask task: cycleTasks) {
                        //并发检测
                        ConcurrentDetection concurrentDetection = new ConcurrentDetection(task,countDownLatch);
                        executorService.execute(concurrentDetection);
                    }
                    try {
                        countDownLatch.await();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                    //更新数据库
                    for (ActiveTask ask: cycleTasks) {
                        //更新采集任务
                        long sensorpkts = ask.getSensorpkts();
                        ask.setSensorpkts(sensorpkts+ask.cyclepkts);
                        long sensorBytes = ask.getSensorBytes();
                        ask.setSensorBytes(sensorBytes+ask.cyclebytes);
                        ActiveTaskManager.updateActiveTaskByTask(ask);

                        //更新任务周期采集情况
                        CycleSensorManager.insert(ask.getId(), ask.cycle, ask.cyclepkts, ask.cyclebytes, ask.peerIpInfoMap.size());

                        //任务重置
                        ask.cycle = "";
                        ask.cyclepkts = 0;
                        ask.cyclebytes = 0;
                        ask.peerIpInfoMap.clear();
                    }
                    //清空上个周期匹配到的任务集合
                    cycleTasks.clear();

                    //回送给CHAIRS，更新数据库
                    /* if (!cycleTasks.isEmpty()) {
                        for (ActiveTask task: cycleTasks) {
                            ActionHandler.returnResults(task);
                        }
                    }*/
                }
                LOG.debug("本周期分离、检测完成");
            }
            //停止策略
            boolean needBuild = false;
            Iterator<ActiveTask> iterator = sensorTasks.iterator();
            while (iterator.hasNext()) {
                ActiveTask task = iterator.next();
                //
                if (SensorStopStrategy.canStop(task) == true) {
                    try {
                        SendStopToHydra hydra = new SendStopToHydra();
                        StopResult result = new StopResult();
                        result.setTicketid(task.getTicketId());

                        //hydra.send(new Gson().toJson(result));
                    } catch (Exception e) {
                        LOG.debug("任务[taskid:" + task.getId() + "停止失败...");
                    } finally {
                        //更新任务状态
                        Long ts = System.currentTimeMillis() / 1000;
                        ActiveTaskManager.updateActiveTaskStatusByTaskId(task.getId(), TaskStatus.FINISHED,ts);

                        needBuild = true;
                        iterator.remove();
                    }
                }
            }

            //重构映射表
            if (needBuild == true) {
                ruleToTasks = new HashMap<>();
                if (!sensorTasks.isEmpty()) {
                    for (ActiveTask task: sensorTasks) {
                        buildRuleToTasks(task);
                    }
                }
            }
        }
    }

    //main
    public static void main(String[] args){
        //test
        /*
       ActiveTask task = new ActiveTask();
       task.setId(1);
       task.setIpString("223.3.108.21/32");
       task.setDirPath("E:/" + task.getId() + "/");

       PcapFileOfflineSplit split = new PcapFileOfflineSplit();
       split.buildRuleToTasks(task);

       PcapFileInfo pcapFileInfo = new PcapFileInfo();
       pcapFileInfo.setFilepath("E:/122200.pcap");

       split.splitPcapFile(pcapFileInfo);
       */
    }
}
