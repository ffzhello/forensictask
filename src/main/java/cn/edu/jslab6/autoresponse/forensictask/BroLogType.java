package cn.edu.jslab6.autoresponse.forensictask;

import java.util.HashSet;
import java.util.Set;

public class BroLogType {
    public static final Set<String> connLogSet = new HashSet<String>(){{
        add("conn.log");
    }};

    /*public static final Set<String> protocolLogSet = new HashSet<String>(){{
        add("dns.log");add("http.log");add("ssl.log");
        add("dhcp.log");add("ftp.log");add("smtp.log");add("snmp.log");
        add("irc.log");add("dnp3.log");add("kerberos.log");add("modbus.log");
        add("modbus_register_change.log");add("mysql.log");add("ntlm.log");add("radius.log");
        add("rdp.log");add("sip.log");add("smb_cmd.log");add("smb_files.log");
        add("smb_mapping.log");add("dce_rpc.log");add("socks.log");add("ssh.log");
        add("syslog.log");add("tunnel.log");
    }};*/

    public static final Set<String> protocolLogSet = new HashSet<String>(){{
        add("dns.log");add("http.log");add("ssl.log");add("ftp.log");add("smtp.log");add("snmp.log");
        add("sip.log");add("ssh.log");
    }};

    /*public static final Set<String> fileLogSet = new HashSet<String>(){{
        add("files.log");add("pe.log");
        add("x509.log");add("known_certs.log");add("known_hosts.log");add("known_modbus.log");
        add("known_services.log");add("software.log");
    }};*/

    public static final Set<String> fileLogSet = new HashSet<String>(){{
        add("files.log");add("pe.log");
        add("x509.log");add("software.log");
    }};

    public static final Set<String> weirdLogSet = new HashSet<String>(){{
        add("weird.log");
    }};
}
