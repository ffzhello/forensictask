package cn.edu.jslab6.autoresponse.forensictask;

import java.io.Serializable;

/**
 * Created by ffzheng on 2017/9/19.
 */


//自定义异常
class MyException extends RuntimeException {

}

class MyException2 extends RuntimeException {
        public MyException2(Throwable cause) {
            super(cause);
        }
        public MyException2(){}
}

public class TestStatic implements Serializable {

    private String str;
    private Integer in;

    public TestStatic(String str, Integer in) {
        this.str = str;
        this.in = in;
    }
    public TestStatic() {

    }

    public static void test() throws MyException{
        throw new MyException();
    }

    public static void test2() {
        try {
            test();
        }catch (MyException e) {
            e.printStackTrace();
            MyException2 ex = new MyException2();
            ex.initCause(e);
            throw e;
        }
    }

    public static void p (char[] chs) {
        chs[0] = 'k';
    }
    public static void main(String[] args) {
        char[] ch = {'a','b'};
        TestStatic ts = new TestStatic();
        ts.p(ch);
        System.out.println(ch);
    }
}
