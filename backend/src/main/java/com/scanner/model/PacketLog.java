package com.scanner.model;

public class PacketLog {
    private String time;
    private String protocol;
    private String src;
    private String dst;
    private int len;
    private String info;

    public PacketLog() {}

    public PacketLog(String time, String protocol, String src, String dst, int len, String info) {
        this.time = time;
        this.protocol = protocol;
        this.src = src;
        this.dst = dst;
        this.len = len;
        this.info = info;
    }

    public String getTime() {
        return time;
    }

    public void setTime(String time) {
        this.time = time;
    }

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getSrc() {
        return src;
    }

    public void setSrc(String src) {
        this.src = src;
    }

    public String getDst() {
        return dst;
    }

    public void setDst(String dst) {
        this.dst = dst;
    }

    public int getLen() {
        return len;
    }

    public void setLen(int len) {
        this.len = len;
    }

    public String getInfo() {
        return info;
    }

    public void setInfo(String info) {
        this.info = info;
    }
}
