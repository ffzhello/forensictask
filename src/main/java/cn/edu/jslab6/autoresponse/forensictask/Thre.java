package cn.edu.jslab6.autoresponse.forensictask;

import java.util.*;
import java.util.concurrent.CountDownLatch;

/**
 * Created by ffzheng on 2018/6/25.
 */

class AA {
    public int x = 0;
    public int y = 0;
}
public class Thre implements Runnable {

    private CountDownLatch countDownLatch = null;

    public Thre(CountDownLatch countDownLatch) {
        this.countDownLatch = countDownLatch;
    }

    @Override
    public void run() {
            System.out.println("xxx");
            countDownLatch.countDown();
    }

    public static void main(String[] args) {
        Map<Integer, List> map = new HashMap<>();
        AA a = new AA();
        a.x = 1;
        AA b = new AA();
        b.x = 2;
        AA c = new AA();
        c.x = 3;

        List<AA> list1 = new ArrayList<>();
        list1.add(a);
        list1.add(b);
        map.put(1,list1);

        List<AA> list2 = new ArrayList<>();
        list2.add(a);
        list2.add(b);
        list2.add(c);
        map.put(2,list2);

        for(Iterator<Map.Entry<Integer, List>> it = map.entrySet().iterator(); it.hasNext();){
            Map.Entry<Integer, List> item = it.next();
            int i = item.getKey();
            List<AA> list = item.getValue();
            for (Iterator<AA> iterator = list.iterator(); iterator.hasNext();) {
                AA aa = iterator.next();
                if (i == 1 && aa.x == 1) {
                    aa.y = 1;
                    iterator.remove();
                }
            }
            if (list.isEmpty()) {
                it.remove();
            }
        }

        for (Map.Entry<Integer, List> entry: map.entrySet()) {
            Integer i = entry.getKey();
            System.out.print(i + ":");
            List<AA> stringList = entry.getValue();
            for (AA aaa: stringList) {
                System.out.println(aaa.x +","+aaa.y);
            }
            System.out.println();
        }

    }
}
